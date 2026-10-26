//! `HookDecide` `claude_permission_verdict` — the verdict the CLI hook gives
//! Claude Code's permission dialog.
//!
//! Claude raises `PermissionRequest` only after `PreToolUse` let the call
//! continue. A pending Guard notice that expects an explicit answer denies
//! Claude's dialog and sends Claude to the Guard approval question; any other
//! notice is a review that shows its reason and defers to Claude's dialog.
//! Both predicates are the ones the resident's daemon path answers the same
//! dialog with (`hook_direct::claude_permission_text`), so the two paths read
//! a notice the same way.
//!
//! Without a notice the CLI path, unlike the daemon path, still reviews the
//! runtime artifact: the most restrictive of its configured action and, for a
//! package request, the package evaluation's action decides. A review-tier
//! action defers to Claude's dialog, a terminal one denies it, and anything
//! weaker is no decision.
//!
//! The approval invariant holds here: every review offers a way to approve,
//! Claude's own dialog for `review` and the Guard approval question for
//! `guard_question`. Only `block` and `sandbox-required` deny, and they are
//! not reviews. A malformed request is a `native_hook_decision_*` error, which
//! the transport answers with the host outage response, never a verdict.

use guard_contracts::{
    most_restrictive_of, normalize_guard_action, ClaudePermissionVerdictInputsV1,
    ClaudePermissionVerdictV1, GuardAction, CLAUDE_PERMISSION_ARTIFACT_POLICY_FACT,
    DEFAULT_UNKNOWN_GUARD_ACTION,
};
use serde_json::Value;

use crate::hook_direct::claude_permission_text::{notice_field, notice_prefers_ask_user_question};

const INVALID: &str = "native_hook_decision_claude_permission_invalid";
/// The reason the host response carries when Claude is sent to the Guard
/// approval question; the deny message itself is that question.
const GUARD_QUESTION_REASON: &str = "HOL Guard is routing this approval through AskUserQuestion.";
/// The reason shown when neither the notice nor the artifact supplies one.
const DEFAULT_REASON: &str = "HOL Guard is reviewing this Claude approval prompt.";

fn passthrough() -> ClaudePermissionVerdictV1 {
    ClaudePermissionVerdictV1 {
        verdict: "passthrough".to_owned(),
        policy_action: None,
        offers_approval: false,
        reason: None,
        reason_from_artifact: false,
        artifact_action: None,
    }
}

fn reviewed(
    verdict: &str,
    policy_action: GuardAction,
    reason: &str,
    artifact_action: Option<GuardAction>,
) -> ClaudePermissionVerdictV1 {
    ClaudePermissionVerdictV1 {
        verdict: verdict.to_owned(),
        policy_action: Some(policy_action.as_str().to_owned()),
        offers_approval: verdict != "deny",
        reason: Some(reason.to_owned()),
        reason_from_artifact: artifact_action.is_some(),
        artifact_action: artifact_action.map(|action| action.as_str().to_owned()),
    }
}

/// The verdict, or the fact the resident needs before it can give one.
pub(crate) fn claude_permission_verdict(
    inputs: &ClaudePermissionVerdictInputsV1,
) -> Result<Result<ClaudePermissionVerdictV1, &'static str>, String> {
    let invalid = || INVALID.to_owned();
    if let Some(notice) = &inputs.notice {
        // A notice decides on its own; artifact facts would mean the
        // transport decided to gather them.
        if inputs.artifact_policy.is_some() {
            return Err(invalid());
        }
        if notice_prefers_ask_user_question(notice) {
            return Ok(Ok(reviewed(
                "guard_question",
                GuardAction::Block,
                GUARD_QUESTION_REASON,
                None,
            )));
        }
        let reason = notice_field(Some(notice), "reason").unwrap_or(DEFAULT_REASON);
        return Ok(Ok(reviewed(
            "review",
            GuardAction::RequireReapproval,
            reason,
            None,
        )));
    }
    if !inputs.runtime_artifact_present {
        if inputs.artifact_policy.is_some() {
            return Err(invalid());
        }
        return Ok(Ok(passthrough()));
    }
    let Some(policy) = &inputs.artifact_policy else {
        return Ok(Err(CLAUDE_PERMISSION_ARTIFACT_POLICY_FACT));
    };
    let configured = GuardAction::from_canonical(&policy.config_action).ok_or_else(invalid)?;
    let action = match &policy.package_action {
        Some(package) => most_restrictive_of(
            configured,
            normalize_guard_action(
                &Value::String(package.clone()),
                DEFAULT_UNKNOWN_GUARD_ACTION,
            ),
        ),
        None => configured,
    };
    Ok(Ok(match action {
        GuardAction::Block | GuardAction::SandboxRequired => {
            reviewed("deny", action, DEFAULT_REASON, Some(action))
        }
        GuardAction::Review | GuardAction::RequireReapproval => reviewed(
            "review",
            GuardAction::RequireReapproval,
            DEFAULT_REASON,
            Some(action),
        ),
        GuardAction::Allow | GuardAction::Warn => passthrough(),
    }))
}

#[cfg(test)]
#[path = "hook_decision_claude_permission_verdict_tests.rs"]
mod tests;
