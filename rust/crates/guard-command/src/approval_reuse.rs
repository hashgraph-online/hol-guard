//! `approval_reuse.py` — the pure composition lattice for recomputed policy
//! vs saved approval evidence.
//!
//! A saved approval is evidence that an exact, previously reviewed request may
//! proceed; it cannot lower a newly computed `sandbox-required` or `block`.
//! This module composes the recomputed action with the saved decision and
//! returns a review-floor decision, never execution authorization.

use serde::Serialize;
use serde_json::Value;

use crate::action_lattice::{
    normalize_guard_action_result, GuardActionNormalization, UNKNOWN_GUARD_ACTION_REASON,
};
use crate::effect_decision::GuardAction;

pub type ApprovalReuseStatus = &'static str;
// "accepted" | "rejected" | "not-applicable"

pub const APPROVAL_REUSE_ACCEPTED: &str = "approval_reuse_accepted";
pub const APPROVAL_REUSE_NO_SAVED_DECISION: &str = "approval_reuse_no_saved_decision";
pub const APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN: &str = "approval_reuse_current_action_unknown";
pub const APPROVAL_REUSE_SAVED_ACTION_UNKNOWN: &str = "approval_reuse_saved_action_unknown";
pub const APPROVAL_REUSE_CURRENT_BLOCK: &str = "approval_reuse_current_block";
pub const APPROVAL_REUSE_SANDBOX_REQUIRED: &str = "approval_reuse_sandbox_required";
pub const APPROVAL_REUSE_REAPPROVAL_REQUIRED: &str = "approval_reuse_reapproval_required";
pub const APPROVAL_REUSE_CURRENT_ACTION_NOT_REVIEW: &str =
    "approval_reuse_current_action_not_review";
pub const APPROVAL_REUSE_SAVED_ACTION_NOT_ALLOW: &str = "approval_reuse_saved_action_not_allow";
pub const APPROVAL_REUSE_SAVED_BLOCK: &str = "approval_reuse_saved_block";
pub const APPROVAL_REUSE_CLAIM_FAILED: &str = "approval_reuse_claim_failed";
pub const APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED: &str =
    "approval_reuse_launch_identity_unverified";
pub const APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM: &str =
    "approval_reuse_context_changed_after_claim";

/// `ApprovalReuseDecision` (:58-72). Wire field names are the Python
/// `to_evidence` keys exactly — `commands_hook_native_copilot.py` depends on
/// them, so a rename would silently break consumers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ApprovalReuseDecision {
    pub action: GuardAction,
    pub status: ApprovalReuseStatus,
    pub reason_code: String,
    pub current_action: GuardAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_action: Option<GuardAction>,
    pub should_claim: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_normalization_reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_normalization_reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_current_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_saved_action: Option<String>,
    pub original_current_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_saved_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_artifact_hash_is_context_token: Option<bool>,
}

impl ApprovalReuseDecision {
    pub fn accepted(&self) -> bool {
        self.status == "accepted"
    }
}

/// `evaluate_approval_reuse` (:128-267).
///
/// `current_action`/`saved_action` are untyped `Value` inputs (a stored row may
/// carry a malformed action). `saved_decision_present` overrides the `is_some`
/// present-check so untyped persistence callers can distinguish absence from a
/// null stored action.
pub fn evaluate_approval_reuse(
    current_action: &Value,
    saved_action: Option<&Value>,
    saved_decision_present: Option<bool>,
    validation_reason: Option<&str>,
    fresh_local_approval: bool,
    durable_exact_approval: bool,
) -> ApprovalReuseDecision {
    let current = normalize_guard_action_result(current_action, GuardAction::Block);
    let present = match saved_decision_present {
        Some(p) => p,
        None => saved_action.is_some(),
    };
    if !present {
        let reason_code = if current.reason_code == Some(UNKNOWN_GUARD_ACTION_REASON) {
            APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN
        } else {
            APPROVAL_REUSE_NO_SAVED_DECISION
        };
        return decision(
            current.action,
            if current.reason_code.is_some() {
                "rejected"
            } else {
                "not-applicable"
            },
            reason_code,
            &current,
            None,
            false,
        );
    }

    let saved = normalize_guard_action_result(
        saved_action.unwrap_or(&Value::Null),
        GuardAction::RequireReapproval,
    );
    // most_restrictive over the normalized actions, unknown->block.
    let mut conservative_action = if current.action.severity() >= saved.action.severity() {
        current.action
    } else {
        saved.action
    };

    if current.reason_code.is_some() {
        return decision(
            conservative_action,
            "rejected",
            APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN,
            &current,
            Some(&saved),
            false,
        );
    }
    if let Some(validation_reason) = validation_reason {
        if validation_reason == "approval_reuse_integrity_failure" {
            // A tampered authority cannot be ignored even when current policy
            // independently allows; strengthen to require-reapproval.
            if GuardAction::RequireReapproval.severity() > conservative_action.severity() {
                conservative_action = GuardAction::RequireReapproval;
            }
        }
        return decision(
            conservative_action,
            "rejected",
            validation_reason,
            &current,
            Some(&saved),
            false,
        );
    }
    if saved.reason_code.is_some() {
        return decision(
            conservative_action,
            "rejected",
            APPROVAL_REUSE_SAVED_ACTION_UNKNOWN,
            &current,
            Some(&saved),
            false,
        );
    }
    if saved.action == GuardAction::Block {
        return decision(
            GuardAction::Block,
            "accepted",
            APPROVAL_REUSE_SAVED_BLOCK,
            &current,
            Some(&saved),
            false,
        );
    }
    if current.action == GuardAction::Block {
        return decision(
            GuardAction::Block,
            "rejected",
            APPROVAL_REUSE_CURRENT_BLOCK,
            &current,
            Some(&saved),
            false,
        );
    }
    if current.action == GuardAction::SandboxRequired {
        return decision(
            GuardAction::SandboxRequired,
            "rejected",
            APPROVAL_REUSE_SANDBOX_REQUIRED,
            &current,
            Some(&saved),
            false,
        );
    }
    if current.action == GuardAction::RequireReapproval
        && (fresh_local_approval || durable_exact_approval)
        && saved.action == GuardAction::Allow
    {
        return decision(
            GuardAction::Allow,
            "accepted",
            APPROVAL_REUSE_ACCEPTED,
            &current,
            Some(&saved),
            true,
        );
    }
    if current.action == GuardAction::RequireReapproval {
        return decision(
            conservative_action,
            "rejected",
            APPROVAL_REUSE_REAPPROVAL_REQUIRED,
            &current,
            Some(&saved),
            false,
        );
    }
    if current.action == GuardAction::Review && saved.action == GuardAction::Allow {
        return decision(
            GuardAction::Allow,
            "accepted",
            APPROVAL_REUSE_ACCEPTED,
            &current,
            Some(&saved),
            true,
        );
    }
    if saved.action == GuardAction::Allow {
        return decision(
            current.action,
            "not-applicable",
            APPROVAL_REUSE_CURRENT_ACTION_NOT_REVIEW,
            &current,
            Some(&saved),
            false,
        );
    }
    decision(
        conservative_action,
        "rejected",
        APPROVAL_REUSE_SAVED_ACTION_NOT_ALLOW,
        &current,
        Some(&saved),
        false,
    )
}

fn decision(
    action: GuardAction,
    status: ApprovalReuseStatus,
    reason_code: &str,
    current: &GuardActionNormalization,
    saved: Option<&GuardActionNormalization>,
    should_claim: bool,
) -> ApprovalReuseDecision {
    ApprovalReuseDecision {
        action,
        status,
        reason_code: reason_code.to_owned(),
        current_action: current.action,
        saved_action: saved.map(|s| s.action),
        should_claim,
        current_normalization_reason_code: current.reason_code.map(str::to_owned),
        saved_normalization_reason_code: saved.and_then(|s| s.reason_code.map(str::to_owned)),
        original_current_action: current.original_action.clone(),
        original_saved_action: saved.and_then(|s| s.original_action.clone()),
        original_current_type: current.original_type.to_owned(),
        original_saved_type: saved.map(|s| s.original_type.to_owned()),
        saved_artifact_hash_is_context_token: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_approval_reuse, ApprovalReuseDecision};
    use serde_json::Value;

    // `testdata/approval_reuse_oracle.json` — generated by running Python
    // `evaluate_approval_reuse` over the full input grid (2916 cases covering
    // all 13 reason codes). Each row asserts (action, status, reason_code,
    // should_claim, saved_action) parity.
    #[test]
    fn approval_reuse_python_oracle() {
        let raw = include_str!("../testdata/approval_reuse_oracle.json");
        let rows: Vec<Value> = serde_json::from_str(raw).expect("oracle parse");
        assert_eq!(rows.len(), 2916, "oracle corpus truncated");
        let mut checked = 0usize;
        for (i, row) in rows.iter().enumerate() {
            let current = &row["current_action"];
            let saved = row["saved_action"].clone();
            let sdp = row["saved_decision_present"].as_bool();
            let vr = row["validation_reason"].as_str();
            let fla = row["fresh_local_approval"].as_bool().unwrap();
            let dex = row["durable_exact_approval"].as_bool().unwrap();
            let d: ApprovalReuseDecision = evaluate_approval_reuse(
                current,
                if saved.is_null() { None } else { Some(&saved) },
                sdp,
                vr,
                fla,
                dex,
            );
            let expect = &row["expect"];
            let want_action = expect["action"].as_str().unwrap();
            let want_status = expect["status"].as_str().unwrap();
            let want_reason = expect["reason_code"].as_str().unwrap();
            let want_claim = expect["should_claim"].as_bool().unwrap();
            let want_saved = expect["saved_action_out"].as_str();
            assert_eq!(d.action.as_str(), want_action, "row {i} action: {row}");
            assert_eq!(d.status, want_status, "row {i} status: {row}");
            assert_eq!(d.reason_code, want_reason, "row {i} reason: {row}");
            assert_eq!(d.should_claim, want_claim, "row {i} claim: {row}");
            assert_eq!(
                d.saved_action.map(|a| a.as_str()),
                want_saved,
                "row {i} saved_action: {row}"
            );
            checked += 1;
        }
        assert_eq!(checked, 2916);
    }
}
