//! `hook_local_cli_rule`: the daemon's custom extension rule for a native
//! `PreToolUse`, decided by the same launch identity and grant read the
//! direct lane uses.
//!
//! `allowed` is `native_local_cli_block_response`: while any custom block
//! rule exists, a command the edge allowed is blocked when its grant blocks
//! it, and blocked as unverified when its identity or grant cannot be
//! checked. `review` is `native_local_cli_grant_response`: a block applies to
//! any review, and an allow lifts only an overridable review due to
//! non-recognition alone. The daemon renders the verdict.

use guard_contracts::{
    HookLocalCliRuleRequestV1, HookLocalCliRuleResultV1, HOOK_LOCAL_CLI_RULE_REQUEST_SCHEMA,
    HOOK_LOCAL_CLI_RULE_RESULT_SCHEMA,
};
use serde_json::Value;

use super::block::{ReviewVerdict, Verdict};
use super::{LaunchEnv, RuleCheck};

/// The one review a custom allow lifts: Rust did not recognise the program.
const GRANT_LIFTABLE_REASON: &str = "native_command_review_required";
const REVIEW_ACTIONS: [&str; 2] = ["review", "require-reapproval"];

/// The daemon's answer for one rule check.
#[derive(Debug, PartialEq)]
pub(crate) enum RuleVerdict {
    None,
    Blocked(String),
    Unverified,
    Allowed,
}

pub(crate) fn evaluate_hook_local_cli_rule_request(
    request: &HookLocalCliRuleRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != HOOK_LOCAL_CLI_RULE_REQUEST_SCHEMA {
        return Err("native_hook_local_cli_rule_schema_mismatch".to_owned());
    }
    let verdict = match request.mode.as_str() {
        "allowed" => allowed_verdict(request),
        "review" => review_verdict(request),
        _ => return Err("native_hook_local_cli_rule_mode_invalid".to_owned()),
    };
    let (verdict, name) = match verdict {
        RuleVerdict::None => ("none", None),
        RuleVerdict::Blocked(name) => ("blocked", Some(name)),
        RuleVerdict::Unverified => ("unverified", None),
        RuleVerdict::Allowed => ("allowed", None),
    };
    crate::resident_protocol::encode_response(&HookLocalCliRuleResultV1 {
        schema: HOOK_LOCAL_CLI_RULE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        status: "ok".to_owned(),
        verdict: verdict.to_owned(),
        name,
    })
}

fn check(request: &HookLocalCliRuleRequestV1) -> RuleCheck<'_> {
    RuleCheck {
        payload: Some(&request.payload),
        harness: "",
        // A relative workspace is no launch directory, as an absent one is not.
        workspace: request.workspace.as_deref().unwrap_or_default(),
        home_dir: &request.home_dir,
        guard_home: &request.guard_home,
        recording_only: false,
        launch_env: launch_env(request),
    }
}

/// The daemon's home and environment, when it sent both.
fn launch_env(request: &HookLocalCliRuleRequestV1) -> Option<LaunchEnv<'_>> {
    Some(LaunchEnv {
        user_home: request.user_home.as_deref()?,
        env: request.env.as_ref()?,
    })
}

/// `native_local_cli_block_response`. The identity steps run only while some
/// custom block rule exists; with one, a command whose launch or grant cannot
/// be checked is blocked as unverified.
pub(crate) fn allowed_verdict(request: &HookLocalCliRuleRequestV1) -> RuleVerdict {
    if request
        .native_result
        .get("minimum_action")
        .and_then(Value::as_str)
        != Some("allow")
        || !crate::local_cli_hook_contained::has_block_rules_at(
            &request.store_path,
            &request.guard_home,
        )
    {
        return RuleVerdict::None;
    }
    let check = check(request);
    let launched = match super::launch_for(
        &request.payload,
        check.workspace,
        check.home_dir,
        check.launch_env,
    ) {
        Ok(Some(launched)) => launched,
        Ok(None) => return RuleVerdict::None,
        Err(()) => return RuleVerdict::Unverified,
    };
    match super::grant(&launched, check.home_dir, check.guard_home) {
        Ok(Verdict::Unchanged) => RuleVerdict::None,
        Ok(Verdict::Blocked(name)) => RuleVerdict::Blocked(name),
        Ok(Verdict::Unverified) | Err(()) => RuleVerdict::Unverified,
    }
}

/// `native_local_cli_grant_response`. A failed identity or grant read leaves
/// the review standing.
pub(crate) fn review_verdict(request: &HookLocalCliRuleRequestV1) -> RuleVerdict {
    let result = &request.native_result;
    if !result
        .get("policy_action")
        .and_then(Value::as_str)
        .is_some_and(|action| REVIEW_ACTIONS.contains(&action))
    {
        return RuleVerdict::None;
    }
    match super::review_grant(&check(request)) {
        Some(ReviewVerdict::Blocked(name)) => RuleVerdict::Blocked(name),
        Some(ReviewVerdict::Allowed)
            if result.get("reason_code").and_then(Value::as_str) == Some(GRANT_LIFTABLE_REASON)
                && crate::hook_direct::saved_decision::overridable(result) =>
        {
            RuleVerdict::Allowed
        }
        _ => RuleVerdict::None,
    }
}

#[cfg(test)]
#[path = "hook_direct_local_cli_rule_op_tests.rs"]
mod tests;
