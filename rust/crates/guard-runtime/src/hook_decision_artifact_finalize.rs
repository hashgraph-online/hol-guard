//! `HookDecide` `artifact_finalize` and `artifact_browser_outcome` — the
//! artifact hook's final-action settle.
//!
//! A verdict can still change after review: Watch mode executes the policy it
//! observed, a silent denial closes a review, and a browser approval resolves
//! it. `artifact_browser_outcome` says whether a browser outcome settles the
//! hook and how the hook ends; `artifact_finalize` says what the final action,
//! the decision record, the evidence and the persisted receipt become. The
//! transport gathers the facts, applies the answer and decides nothing itself.
//!
//! The approval invariant holds here: nothing in a settle narrows an approval
//! choice. Only a browser resolution makes a `review` verdict final, and it
//! carries the user's `allow` or a terminal `block` or `sandbox-required`; a
//! browser outcome that is none of the three settles nothing and leaves the
//! review offered as Allow once and Always allow.

use guard_contracts::{
    normalize_guard_action, ArtifactBrowserOutcomeInputsV1, ArtifactBrowserOutcomeV1,
    ArtifactEvidenceFieldsV1, ArtifactEvidencePatchV1, ArtifactFinalizeInputsV1,
    ArtifactFinalizeV1, ArtifactReceiptFieldsV1, ArtifactResolutionEvidenceV1, GuardAction,
};
use serde_json::Value;

const BROWSER: &str = "browser";
/// The `user_override` a browser resolution records on the receipt.
const BROWSER_OVERRIDE: &str = "browser-approval";
/// The evidence entry source a browser resolution appends to the receipt.
const RESOLUTION_SOURCE: &str = "browser_approval_resolution";
/// The evidence entries a settle rewrites: the policy composition's.
const COMPOSITION_SOURCE: &str = "policy_composition";
/// Cloud failures a new decision keeps from the old one: the package review
/// could not reach the cloud, which is still true after the action changes.
const CLOUD_REASON_CODES: [&str; 4] = [
    "cloud_auth_error",
    "cloud_http_error",
    "cloud_timeout",
    "cloud_validation_error",
];

/// An action the lattice does not know settles as the strictest one.
fn normalized(raw: &str) -> GuardAction {
    normalize_guard_action(&Value::String(raw.to_owned()), GuardAction::Block)
}

/// Python's `value or fallback` over optional text: empty text falls through.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}

pub(crate) fn artifact_finalize(inputs: &ArtifactFinalizeInputsV1) -> ArtifactFinalizeV1 {
    let previous = normalized(&inputs.previous_action);
    let action = normalized(&inputs.policy_action);
    let observed = inputs.observed_policy_action.as_deref().map(normalized);
    let browser = inputs.approval_source.as_deref() == Some(BROWSER);
    let terminal = matches!(action, GuardAction::Block | GuardAction::SandboxRequired);
    // A terminal browser outcome that names no request answers the first one
    // that was queued; an allow answers only the request that was resolved.
    let resolved = inputs.approval_request_id.clone().or_else(|| {
        if browser && terminal {
            inputs.queued_request_id.clone()
        } else {
            None
        }
    });
    let refresh_copy = previous != action;
    let observed_supply_chain_action =
        match (&observed, refresh_copy && inputs.supply_chain_present) {
            (Some(observed), true) => Some(
                inputs
                    .supply_chain_action
                    .as_deref()
                    .map_or(*observed, normalized)
                    .as_str()
                    .to_owned(),
            ),
            _ => None,
        };
    let appended_evidence = if browser {
        vec![ArtifactResolutionEvidenceV1 {
            source: RESOLUTION_SOURCE.to_owned(),
            initial_action: inputs.initial_policy_action.clone(),
            authoritative_action: action.as_str().to_owned(),
            approval_request_id: resolved.clone(),
        }]
    } else {
        Vec::new()
    };
    ArtifactFinalizeV1 {
        action: action.as_str().to_owned(),
        observed_action: observed.map(|item| item.as_str().to_owned()),
        decision_reason: if browser {
            BROWSER_OVERRIDE.to_owned()
        } else {
            action.as_str().to_owned()
        },
        cloud_reason_code: inputs
            .package_review_cloud_reason_code
            .clone()
            .filter(|code| CLOUD_REASON_CODES.contains(&code.as_str())),
        refresh_copy,
        observed_supply_chain_action,
        drop_terminal_action: observed.is_some(),
        evidence_patch: ArtifactEvidencePatchV1 {
            source: COMPOSITION_SOURCE.to_owned(),
            fields: ArtifactEvidenceFieldsV1 {
                authoritative_action: action.as_str().to_owned(),
                observed_policy_action: observed.map(|item| item.as_str().to_owned()),
            },
        },
        receipt: ArtifactReceiptFieldsV1 {
            policy_decision: action.as_str().to_owned(),
            approval_source: non_empty(inputs.approval_source.as_deref())
                .or(inputs.receipt_approval_source.as_deref())
                .map(str::to_owned),
            approval_request_id: non_empty(resolved.as_deref())
                .or(inputs.receipt_approval_request_id.as_deref())
                .map(str::to_owned),
            user_override: if browser {
                Some(BROWSER_OVERRIDE.to_owned())
            } else {
                inputs.receipt_user_override.clone()
            },
            appended_evidence,
        },
    }
}

fn unsettled() -> ArtifactBrowserOutcomeV1 {
    ArtifactBrowserOutcomeV1 {
        settle: false,
        action: None,
        approval_source: None,
        emit_native_allow: false,
        finish_without_render: false,
    }
}

/// A browser outcome settles the hook only as an approval the user gave
/// (`allow`) or a terminal verdict (`block`, `sandbox-required`). An approval
/// ends the hook once its receipt is recorded: a tool call is answered by the
/// harness's own allow, and every other event is answered here with an empty
/// reason. A terminal verdict goes on to render like any other terminal one.
pub(crate) fn artifact_browser_outcome(
    inputs: &ArtifactBrowserOutcomeInputsV1,
) -> ArtifactBrowserOutcomeV1 {
    let settle = |action: GuardAction, emit_native_allow: bool, finish_without_render: bool| {
        ArtifactBrowserOutcomeV1 {
            settle: true,
            action: Some(action.as_str().to_owned()),
            approval_source: Some(BROWSER.to_owned()),
            emit_native_allow,
            finish_without_render,
        }
    };
    match inputs.decision.as_str() {
        "allow" => settle(GuardAction::Allow, inputs.event != "PreToolUse", true),
        "block" => settle(GuardAction::Block, false, false),
        "sandbox-required" => settle(GuardAction::SandboxRequired, false, false),
        _ => unsettled(),
    }
}

#[cfg(test)]
#[path = "hook_decision_artifact_finalize_tests.rs"]
mod tests;
