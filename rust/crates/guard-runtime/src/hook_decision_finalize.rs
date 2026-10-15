//! Final-action settlement for the generic hook path: Watch mode, the
//! unprompted-review block, audit evidence, receipt and activity
//! dispositions, and the post-claim reuse inputs.

use guard_contracts::{
    most_restrictive_of, GuardAction, GuardActionNormalization, HookActivityV1,
    HookCompositionInputsV1, HookFinalV1, HookSettledInputsV1, HookSilentReviewV1,
    PostClaimInputsV1,
};
use serde_json::{json, Map, Value};

use crate::hook_decision_compose::{Composed, BENIGN_DEFAULT_REASON};
use crate::hook_decision_directive::DirectiveFacts;
use crate::hook_decision_directive::{directive, is_blocking, is_post_event, is_pre_event};

const CONTEXT_CHANGED_AFTER_CLAIM: &str = "approval_reuse_context_changed_after_claim";
const CLAIM_FAILED: &str = "approval_reuse_claim_failed";
const INTEGRITY_FAILURE: &str = "approval_reuse_integrity_failure";

pub(crate) fn parse_action(raw: &str) -> Result<GuardAction, String> {
    GuardAction::from_canonical(raw).ok_or_else(|| "native_hook_decision_action_invalid".to_owned())
}

fn text(action: Option<GuardAction>) -> Value {
    action.map_or(Value::Null, |item| Value::from(item.as_str()))
}

fn normalized(item: Option<&GuardActionNormalization>) -> Value {
    item.map_or(Value::Null, |entry| Value::from(entry.action.as_str()))
}

pub(crate) fn post_claim(
    inputs: &PostClaimInputsV1,
) -> Result<(GuardAction, Option<&'static str>), String> {
    let current = parse_action(&inputs.current_policy_action)?;
    let reuse = parse_action(&inputs.reuse_action)?;
    let mut reason = (inputs.post_claim_refresh_failed || inputs.context_changed)
        .then_some(CONTEXT_CHANGED_AFTER_CLAIM);
    if inputs.has_ignored_integrity {
        reason = Some(INTEGRITY_FAILURE);
    }
    if inputs.claim_row_invalid {
        reason = Some(CLAIM_FAILED);
    }
    // An unclaimed allow found by the fresh lookup is evidence only; the
    // already-claimed exact row may satisfy a freshly recomputed review.
    let saved_allow = inputs.reuse_saved_action.as_ref().and_then(Value::as_str) == Some("allow");
    let mut action = if saved_allow && reuse == GuardAction::Allow {
        current
    } else {
        reuse
    };
    if reason.is_some() {
        action = most_restrictive_of(action, GuardAction::RequireReapproval);
    }
    Ok((action, reason))
}

fn policy_composition(
    c: &Composed,
    s: &HookSettledInputsV1,
    source: Option<&str>,
    authoritative: GuardAction,
    observed: Option<GuardAction>,
) -> Map<String, Value> {
    let mut map = Map::new();
    let mut put = |key: &str, value: Value| {
        map.insert(key.to_owned(), value);
    };
    put(
        "current_config_action",
        Value::from(c.current_config.as_str()),
    );
    put(
        "configured_policy_action",
        Value::from(c.configured.action.as_str()),
    );
    put(
        "configured_default_disposition",
        Value::from(if c.relaxed {
            "relaxed_verified_benign"
        } else {
            "applied"
        }),
    );
    put(
        "configured_default_disposition_reason_code",
        if c.relaxed {
            Value::from(BENIGN_DEFAULT_REASON)
        } else {
            Value::Null
        },
    );
    put("trusted_cli_override", normalized(c.cli.as_ref()));
    put(
        "untrusted_hook_payload_hint",
        normalized(c.payload.as_ref()),
    );
    put(
        "untrusted_hook_payload_hint_disposition",
        c.payload_disposition.map_or(Value::Null, Value::from),
    );
    put(
        "untrusted_hook_payload_hint_reason_code",
        c.ignored_payload_reason.map_or(Value::Null, Value::from),
    );
    put(
        "daemon_hint_disposition",
        c.daemon_disposition.map_or(Value::Null, Value::from),
    );
    put(
        "daemon_hint_reason_code",
        c.daemon_reason_code.map_or(Value::Null, Value::from),
    );
    put(
        "daemon_hint_trust",
        if c.daemon_disposition.is_some() {
            Value::from("untrusted_hook_payload")
        } else {
            Value::Null
        },
    );
    put(
        "daemon_status",
        c.daemon_status.clone().map_or(Value::Null, Value::from),
    );
    put(
        "fail_mode",
        c.fail_mode.clone().map_or(Value::Null, Value::from),
    );
    put(
        "current_composed_action",
        Value::from(s.current_policy_action.clone()),
    );
    put(
        "saved_policy_action",
        s.stored_policy_action
            .clone()
            .map_or(Value::Null, Value::from),
    );
    put(
        "approval_reuse_source",
        source.map_or(Value::Null, Value::from),
    );
    put("local_tool_grant", Value::from(s.tool_grant_applied));
    put("authoritative_action", Value::from(authoritative.as_str()));
    put("observed_policy_action", text(observed));
    map
}

fn evidence_tail(
    c: &Composed,
    s: &HookSettledInputsV1,
    observed: Option<GuardAction>,
) -> Vec<Value> {
    let mut tail = Vec::new();
    if let (true, Some(identity)) = (s.tool_grant_applied, &s.tool_grant_identity) {
        tail.push(json!({
            "source": "trusted_local_tool_grant",
            "applied": true,
            "tool_identity_hash": identity.get("tool_identity_hash").cloned().unwrap_or(Value::Null),
            "capability": identity.get("capability").cloned().unwrap_or(Value::Null),
        }));
    }
    if let Some(reason) = c.ignored_payload_reason {
        tail.push(json!({
            "source": "hook_payload_trust",
            "input_source": "untrusted_hook_payload_hint",
            "status": "ignored",
            "reason_code": reason,
            "classifier": "is_explicitly_benign_tool_action_request",
        }));
    }
    if c.relaxed {
        tail.push(json!({
            "source": "configured_default",
            "input_source": "local_config",
            "status": "relaxed_verified_benign",
            "reason_code": BENIGN_DEFAULT_REASON,
            "classifier": c.relax_classifier,
        }));
    }
    if let Some(disposition) = c.daemon_disposition {
        tail.push(json!({
            "source": "daemon_hint_trust",
            "input_source": "untrusted_hook_payload",
            "status": "monotonic-only",
            "disposition": disposition,
            "reason_code": c.daemon_reason_code,
        }));
    }
    if let Some(action) = observed {
        tail.push(json!({
            "source": "observe_mode",
            "observed_policy_action": action.as_str(),
            "authoritative_action": "allow",
        }));
    }
    for (source, item) in [
        (
            "current_config_action",
            Some(&c.current_config_normalization),
        ),
        ("trusted_cli_override", c.cli.as_ref()),
        ("untrusted_hook_payload_hint", c.payload.as_ref()),
    ] {
        let Some(item) = item.filter(|entry| !entry.recognized()) else {
            continue;
        };
        tail.push(json!({
            "source": "guard_action_normalizer",
            "input_source": source,
            "reason_code": item.reason_code,
            "original_action": item.original_action,
            "original_type": item.original_type,
            "normalized_action": item.action.as_str(),
        }));
    }
    tail
}

fn silent_review_reason(c: &Composed, s: &HookSettledInputsV1) -> &'static str {
    let ask = |item: &GuardActionNormalization| {
        matches!(
            item.action,
            GuardAction::Review | GuardAction::RequireReapproval
        )
    };
    if s.reuse_status == "rejected" {
        "A saved approval does not cover this action under current protection."
    } else if ask(&c.configured) {
        "Current local policy requires review for this action."
    } else if c.cli.as_ref().is_some_and(ask) {
        "The trusted hook invocation requires review for this action."
    } else {
        "No applicable policy or valid saved approval allows this action."
    }
}

pub(crate) fn finalize(
    inputs: &HookCompositionInputsV1,
    c: &Composed,
    s: &HookSettledInputsV1,
) -> Result<HookFinalV1, String> {
    parse_action(&s.current_policy_action)?;
    let mut action = parse_action(&s.reuse_action)?;
    let source = if s.claimed_context {
        Some("claimed_saved_policy_decision")
    } else if s.has_stored_decision {
        Some("saved_policy_decision")
    } else if s.has_ignored_integrity {
        Some("saved_policy_integrity")
    } else if s.saved_decision_present {
        Some("invalidated_saved_policy")
    } else {
        None
    };
    let observed = (s.observe_mode && action > GuardAction::Warn).then_some(action);
    if observed.is_some() {
        action = GuardAction::Allow;
    }
    let composition = policy_composition(c, s, source, action, observed);
    let tail = evidence_tail(c, s, observed);
    let event = c.effective_event.as_str();
    let silent_review = (is_pre_event(event)
        && matches!(action, GuardAction::Review | GuardAction::RequireReapproval)
        && !s.asks_for_approval)
        .then(|| HookSilentReviewV1 {
            action: action.as_str().to_owned(),
            reason: silent_review_reason(c, s).to_owned(),
        });
    if silent_review.is_some() {
        action = GuardAction::Block;
    }
    let record_receipt = !(inputs.harness == "codex"
        && event == "PreToolUse"
        && !is_blocking(action)
        && observed.is_none());
    let status = match s.reuse_status.as_str() {
        known @ ("accepted" | "rejected" | "not-applicable") => known,
        _ => "not-applicable",
    };
    let phase = if is_post_event(event) {
        "post"
    } else if is_pre_event(event) {
        "pre"
    } else {
        "none"
    };
    let activity = HookActivityV1 {
        phase: phase.to_owned(),
        reuse_status: status.to_owned(),
        prompted: silent_review.is_none() && status != "accepted" && action >= GuardAction::Review,
    };
    let replayed = s.replay_artifact_id && (s.payload_action_is_string || silent_review.is_some());
    let directive = directive(&DirectiveFacts {
        harness: &inputs.harness,
        canonical: &inputs.canonical_harness,
        event,
        action,
        observed: observed.is_some(),
        observe_mode: s.observe_mode,
        has_approval_requests_list: s.has_approval_requests_list,
        json: s.json_requested,
        output_stream_present: s.output_stream_present,
        replayed,
    });
    Ok(HookFinalV1 {
        policy_action: action.as_str().to_owned(),
        observed_policy_action: observed.map(|item| item.as_str().to_owned()),
        effective_event_name: c.effective_event.clone(),
        approval_reuse_source: source.map(str::to_owned),
        policy_composition: composition,
        evidence_tail: tail,
        silent_review,
        record_receipt,
        activity,
        directive,
    })
}
