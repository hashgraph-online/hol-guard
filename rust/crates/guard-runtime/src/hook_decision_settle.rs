//! `HookDecide` `copilot_settle` — the Copilot tool-call hook decisions.
//!
//! The transport hands over the resident's tool-call decision, the artifact
//! facts, the native edge verdict and the posture; this query settles the
//! final action (edge floor, Watch downgrade, silent review) and names, in
//! order, the effects the transport runs and the answer it writes. It is pure:
//! the transport supplies `acked_recording_only` only when asked.

use std::sync::LazyLock;

use guard_contracts::{
    normalize_guard_action, CopilotArtifactFactsV1, CopilotEffectV1, CopilotPlanV1,
    CopilotSettleInputsV1, CopilotToolDecisionV1, GuardAction,
};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::hook_decision_compose::edge_floor;

const NO_SAVED_DECISION: &str = "approval_reuse_no_saved_decision";
const ACKED_FACT: &str = "acked_recording_only";
const SAFE_ALTERNATIVE_GUIDANCE: &str = "This action remains blocked. Continue with a safe, \
     permitted alternative that respects the same protection. Do not retry an equivalent \
     command, bypass Guard, or seek permission to run it. If no safe alternative can complete \
     the task, explain the limitation.";
const OPEN_GUARD_MARKER: &str = "open hol guard to approve";
const DEFAULT_HOOK_REASON: &str = "HOL Guard flagged this tool call for review.";

static GUARD_TOKEN_FRAGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)#guard-token=[A-Za-z0-9_~%+-]+(?:\.[A-Za-z0-9_~%+-]+)*")
        .expect("guard token pattern compiles")
});

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    PreToolUse,
    PermissionRequest,
}

/// `Err(fact)` names a missing fact; the transport resubmits with it.
pub(crate) fn settle(
    inputs: &CopilotSettleInputsV1,
) -> Result<Result<CopilotPlanV1, &'static str>, String> {
    let stage = match inputs.stage.as_str() {
        "pre_tool_use" => Stage::PreToolUse,
        "permission_request" => Stage::PermissionRequest,
        _ => return Err("native_hook_decision_stage_invalid".to_owned()),
    };
    let decision = &inputs.decision;
    let effective = effective_action(decision);
    let mut evidence = decision_evidence(decision, effective);
    let approval_reuse = approval_reuse(decision, effective);
    let mut plan = Plan::default();
    let settled = match stage {
        Stage::PreToolUse => match pre_tool_use(inputs, effective, &mut evidence, &mut plan) {
            Ok(action) => action,
            Err(fact) => return Ok(Err(fact)),
        },
        Stage::PermissionRequest => permission_request(inputs, effective, &mut evidence, &mut plan),
    };
    Ok(Ok(CopilotPlanV1 {
        policy_action: settled.as_str().to_owned(),
        approval_reuse,
        scanner_evidence: evidence,
        effects: plan.effects,
        exit_code: plan.exit_code,
    }))
}

#[derive(Default)]
struct Plan {
    effects: Vec<CopilotEffectV1>,
    exit_code: Option<i32>,
}

impl Plan {
    fn push(&mut self, effect: CopilotEffectV1) {
        self.effects.push(effect);
    }

    fn receipt(&mut self, allow: bool, source: &str, action: GuardAction) {
        self.push(CopilotEffectV1::Receipt {
            verdict: if allow { "allow" } else { "block" }.to_owned(),
            decision_source: source.to_owned(),
            policy_action: action.as_str().to_owned(),
        });
    }

    fn activity(
        &mut self,
        inputs: &CopilotSettleInputsV1,
        event: &str,
        action: GuardAction,
        safe: bool,
    ) {
        let reuse_status = activity_reuse_status(inputs.decision.approval_reuse_status.as_deref());
        // A silently reviewed call was never shown to the operator.
        let prompted = !safe
            && was_prompted(
                inputs.decision.current_action.as_deref(),
                action,
                reuse_status,
            );
        self.push(CopilotEffectV1::Activity {
            event: event.to_owned(),
            policy_action: action.as_str().to_owned(),
            prompted,
            reuse_status: reuse_status.to_owned(),
        });
    }

    fn usage(&mut self, action: GuardAction) {
        self.push(CopilotEffectV1::Usage {
            policy_action: action.as_str().to_owned(),
        });
    }
}

fn pre_tool_use(
    inputs: &CopilotSettleInputsV1,
    effective: GuardAction,
    evidence: &mut Vec<Value>,
    plan: &mut Plan,
) -> Result<GuardAction, &'static str> {
    let mut action = effective;
    // The native edge verdict is a non-bypassable floor on the emitted
    // decision; only a hard enforcement verdict floors PreToolUse.
    let floor = edge_floor(inputs.native_edge.as_ref(), Some("PreToolUse"));
    if let Some(edge) = floor {
        action = action.max(edge);
    }
    let mut recording_only = inputs.recording_only;
    if recording_only && floor.is_some() && inputs.posture_watch {
        // A per-app Watch edit the native publisher has not acknowledged yet
        // must not undo an enforcing native verdict.
        recording_only = inputs.acked_recording_only.ok_or(ACKED_FACT)?;
    }
    if recording_only {
        action = observe(inputs, action, evidence, plan);
    }
    let safe = silent_review(inputs, &mut action, evidence, plan);
    let copilot = inputs.harness_is_copilot;
    let summary = &inputs.decision.summary;
    // Copilot review/reapproval continues to PermissionRequest, which owns
    // that activity; PreToolUse records only decisions that end here.
    if matches!(action, GuardAction::Allow | GuardAction::Warn) {
        plan.receipt(true, "pre-tool-hook", action);
        if copilot {
            plan.activity(inputs, "preToolUse", action, safe);
            plan.usage(action);
            plan.push(pretool_response(action, String::new()));
            plan.exit_code = Some(0);
        }
        return Ok(action);
    }
    if is_terminal(action) {
        plan.receipt(false, "pre-tool-hook", action);
        if copilot {
            plan.activity(inputs, "preToolUse", action, safe);
        }
    }
    if copilot {
        plan.usage(action);
        let name = &inputs.artifact.artifact_name;
        let reason = if safe {
            safe_alternative_reason(summary)
        } else if inputs.decision.saved_action.as_deref() == Some("block") {
            format!("HOL Guard blocked {name}. {summary}")
        } else {
            copilot_hook_reason(&[summary, name])
        };
        plan.push(pretool_response(action, reason));
        plan.exit_code = Some(0);
    }
    Ok(action)
}

fn permission_request(
    inputs: &CopilotSettleInputsV1,
    effective: GuardAction,
    evidence: &mut Vec<Value>,
    plan: &mut Plan,
) -> GuardAction {
    let mut action = effective;
    let safe = !inputs.recording_only && silent_review(inputs, &mut action, evidence, plan);
    if inputs.recording_only {
        action = observe(inputs, action, evidence, plan);
    }
    let event = "copilotPermissionRequest";
    let name = &inputs.artifact.artifact_name;
    let summary = &inputs.decision.summary;
    plan.exit_code = Some(0);
    if matches!(action, GuardAction::Allow | GuardAction::Warn) {
        plan.receipt(true, &inputs.decision.source, action);
        plan.activity(inputs, event, action, safe);
        plan.usage(action);
        plan.push(CopilotEffectV1::PermissionResponse {
            behavior: "allow".to_owned(),
            message: None,
            interrupt: None,
        });
        return action;
    }
    plan.receipt(false, "permission-request-hook", action);
    plan.activity(inputs, event, action, safe);
    if is_terminal(action) {
        plan.usage(action);
        let message = if safe {
            safe_alternative_reason(summary)
        } else {
            format!("HOL Guard blocked {name}. {summary}")
        };
        plan.push(CopilotEffectV1::PermissionResponse {
            behavior: "deny".to_owned(),
            message: Some(message),
            interrupt: Some(true),
        });
        return action;
    }
    plan.push(CopilotEffectV1::QueueApproval {
        evaluation_artifact: artifact_record(
            &inputs.artifact,
            &inputs.decision,
            action,
            evidence,
            None,
        ),
        response_payload: response_payload(inputs, action, evidence),
        deny_reason: format!("HOL Guard blocked {name}. {summary}"),
    });
    action
}

/// Watch mode lets a stopping action through and records what it would have done.
fn observe(
    inputs: &CopilotSettleInputsV1,
    action: GuardAction,
    evidence: &mut Vec<Value>,
    plan: &mut Plan,
) -> GuardAction {
    if matches!(action, GuardAction::Allow | GuardAction::Warn) {
        return action;
    }
    evidence.push(json!({
        "source": "observe_mode",
        "observed_policy_action": action.as_str(),
        "authoritative_action": "allow",
    }));
    plan.push(CopilotEffectV1::ObserveQueue {
        executable_action: "allow".to_owned(),
        observed_policy_action: action.as_str().to_owned(),
        changed_fields: changed_fields(&inputs.decision),
    });
    GuardAction::Allow
}

/// Without approval prompts, a review-tier action is stored as a silent
/// review and blocked; returns whether that happened.
fn silent_review(
    inputs: &CopilotSettleInputsV1,
    action: &mut GuardAction,
    evidence: &[Value],
    plan: &mut Plan,
) -> bool {
    if !matches!(
        *action,
        GuardAction::Review | GuardAction::RequireReapproval
    ) || inputs.asks_for_approval
    {
        return false;
    }
    let summary = Some(inputs.decision.summary.as_str());
    plan.push(CopilotEffectV1::SilentReview {
        artifact: artifact_record(
            &inputs.artifact,
            &inputs.decision,
            *action,
            evidence,
            summary,
        ),
    });
    *action = GuardAction::Block;
    true
}

fn artifact_record(
    artifact: &CopilotArtifactFactsV1,
    decision: &CopilotToolDecisionV1,
    action: GuardAction,
    evidence: &[Value],
    risk_summary: Option<&str>,
) -> Map<String, Value> {
    let mut record = Map::new();
    record.insert("artifact_id".into(), json!(artifact.artifact_id));
    record.insert("artifact_name".into(), json!(artifact.artifact_name));
    record.insert("artifact_hash".into(), json!(artifact.artifact_hash));
    record.insert("policy_action".into(), json!(action.as_str()));
    record.insert("changed_fields".into(), json!(changed_fields(decision)));
    record.insert("artifact_type".into(), json!(artifact.artifact_type));
    record.insert("source_scope".into(), json!(artifact.source_scope));
    record.insert("config_path".into(), json!(artifact.config_path));
    record.insert("launch_target".into(), artifact.launch_target.clone());
    if let Some(summary) = risk_summary {
        record.insert("risk_summary".into(), json!(summary));
    }
    record.insert(
        "action_envelope_json".into(),
        artifact.action_envelope_json.clone(),
    );
    record.insert("scanner_evidence".into(), Value::Array(evidence.to_vec()));
    record
}

fn response_payload(
    inputs: &CopilotSettleInputsV1,
    action: GuardAction,
    evidence: &[Value],
) -> Map<String, Value> {
    let (artifact, decision) = (&inputs.artifact, &inputs.decision);
    let mut payload = Map::new();
    payload.insert("recorded".into(), json!(true));
    payload.insert("harness".into(), json!(artifact.canonical_harness));
    payload.insert("artifact_id".into(), json!(artifact.artifact_id));
    payload.insert("artifact_name".into(), json!(artifact.artifact_name));
    payload.insert("artifact_type".into(), json!(artifact.artifact_type));
    payload.insert("policy_action".into(), json!(action.as_str()));
    payload.insert("risk_signals".into(), json!(decision.signals));
    payload.insert("risk_summary".into(), json!(decision.summary));
    payload.insert("launch_summary".into(), artifact.launch_target.clone());
    if let Some(reuse) = approval_reuse(decision, effective_action(decision)) {
        payload.insert("approval_reuse".into(), Value::Object(reuse));
    }
    if !evidence.is_empty() {
        payload.insert("scanner_evidence".into(), Value::Array(evidence.to_vec()));
    }
    payload
}

fn changed_fields(decision: &CopilotToolDecisionV1) -> Vec<String> {
    std::iter::once("runtime_tool_call".to_owned())
        .chain(decision.signals.iter().cloned())
        .collect()
}

fn pretool_response(action: GuardAction, reason: String) -> CopilotEffectV1 {
    let deny = action >= GuardAction::Review;
    CopilotEffectV1::PretoolResponse {
        permission_decision: if deny { "deny" } else { "allow" }.to_owned(),
        reason,
    }
}

fn is_terminal(action: GuardAction) -> bool {
    matches!(action, GuardAction::Block | GuardAction::SandboxRequired)
}

/// The action enforced for the decision. A rejected attempt to reuse prior
/// authority is a fresh-approval boundary, so its review is a reapproval.
fn effective_action(decision: &CopilotToolDecisionV1) -> GuardAction {
    let action =
        normalize_guard_action(&Value::String(decision.action.clone()), GuardAction::Review);
    let stale_prior_authority = decision.approval_reuse_status.as_deref() == Some("rejected")
        && decision
            .approval_reuse_reason_code
            .as_deref()
            .is_some_and(|code| code != NO_SAVED_DECISION);
    if action == GuardAction::Review && stale_prior_authority {
        GuardAction::RequireReapproval
    } else {
        action
    }
}

fn decision_evidence(decision: &CopilotToolDecisionV1, effective: GuardAction) -> Vec<Value> {
    let mut evidence = Vec::new();
    if let Some(code) = &decision.normalization_reason_code {
        evidence.push(json!({
            "source": "guard_action_normalizer",
            "input_source": "stored_tool_policy",
            "reason_code": code,
            "original_action": decision.original_action,
            "normalized_action": effective.as_str(),
        }));
    }
    if let Some(mut reuse) = approval_reuse(decision, effective) {
        reuse.insert("source".into(), json!("approval_reuse"));
        evidence.push(Value::Object(reuse));
    }
    evidence
}

fn approval_reuse(
    decision: &CopilotToolDecisionV1,
    effective: GuardAction,
) -> Option<Map<String, Value>> {
    let code = decision.approval_reuse_reason_code.as_ref()?;
    let mut reuse = Map::new();
    reuse.insert("status".into(), json!(decision.approval_reuse_status));
    reuse.insert("reason_code".into(), json!(code));
    reuse.insert("current_action".into(), json!(decision.current_action));
    reuse.insert("saved_action".into(), json!(decision.saved_action));
    reuse.insert("effective_action".into(), json!(effective.as_str()));
    Some(reuse)
}

fn activity_reuse_status(status: Option<&str>) -> &'static str {
    match status {
        Some("accepted") => "accepted",
        Some("rejected") => "rejected",
        _ => "not-applicable",
    }
}

/// An actual prompt, excluding approvals reused without interaction.
fn was_prompted(current: Option<&str>, action: GuardAction, reuse_status: &str) -> bool {
    let initial = match current.filter(|value| !value.is_empty()) {
        Some(value) => {
            normalize_guard_action(&Value::String(value.to_owned()), GuardAction::Review)
        }
        None => action,
    };
    reuse_status != "accepted" && initial >= GuardAction::Review
}

fn safe_alternative_reason(reason: &str) -> String {
    format!("{} {SAFE_ALTERNATIVE_GUIDANCE}", reason.trim())
        .trim()
        .to_owned()
}

/// Copilot's hook copy: the joined reason, branded, with an approval step.
fn copilot_hook_reason(values: &[&str]) -> String {
    let mut reason = join_hook_reason(values);
    if reason.starts_with("Guard ") {
        reason = format!("HOL {reason}");
    }
    if reason.to_lowercase().contains("approve") {
        return reason;
    }
    format!("{reason} Approve it in HOL Guard, then retry.")
}

/// Join reason parts, keeping the tokenized Open-HOL-Guard copy when a part
/// repeats it without the token.
fn join_hook_reason(values: &[&str]) -> String {
    let mut messages: Vec<String> = Vec::new();
    for value in values {
        let candidate = value.trim();
        if !candidate.is_empty() && !messages.iter().any(|message| message == candidate) {
            messages.push(candidate.to_owned());
        }
    }
    let tokenized = messages.iter().find(|message| {
        let lower = message.to_lowercase();
        lower.contains("guard-token=") && lower.contains(OPEN_GUARD_MARKER)
    });
    if let Some(replacement) = tokenized.cloned() {
        let untokenized = GUARD_TOKEN_FRAGMENT
            .replace_all(&replacement, "")
            .into_owned();
        let mut merged: Vec<String> = Vec::new();
        let mut used_replacement = false;
        for message in &messages {
            if *message == replacement {
                if !used_replacement {
                    merged.push(message.clone());
                    used_replacement = true;
                }
            } else if !untokenized.is_empty() && message.contains(&untokenized) {
                merged.push(message.replacen(&untokenized, &replacement, 1));
                used_replacement = true;
            } else {
                merged.push(message.clone());
            }
        }
        messages.clear();
        for candidate in merged {
            if !messages.contains(&candidate) {
                messages.push(candidate);
            }
        }
    }
    if messages.is_empty() {
        DEFAULT_HOOK_REASON.to_owned()
    } else {
        messages.join(" ")
    }
}

#[cfg(test)]
#[path = "hook_decision_settle_tests.rs"]
mod tests;
