use guard_contracts::PreToolResultV1;

use crate::native_command_program::ProgramRule;

pub(super) fn rule_floor(rule: &ProgramRule, required: bool) -> &'static str {
    if rule.is_compatibility_attribution_only() {
        return "allow";
    }
    if required {
        return if rule.severity == "critical" {
            "block"
        } else {
            "review"
        };
    }
    match rule.default_mode.as_str() {
        "disabled" => "allow",
        "monitor" => "warn",
        "review" | "required" => "review",
        _ => "block",
    }
}

pub(super) fn rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        _ => 5,
    }
}

pub(super) fn strengthen(result: &mut PreToolResultV1, action: &str, reason: &str) {
    if rank(action) > rank(&result.minimum_action) {
        result.minimum_action = action.to_owned();
        result.policy_action = action.to_owned();
        result.decision = if matches!(action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .to_owned();
        result.explicitly_benign = action == "allow";
        result.reason_code = reason.to_owned();
        result.reason = match reason {
            "native_command_extension_evaluation_failed" => {
                "HOL Guard could not evaluate the extension controls for this command. Check Guard diagnostics before retrying."
            }
            "native_command_extension_uncertain" => {
                "HOL Guard requires review because it could not match this command to its extension permissions."
            }
            _ => "HOL Guard requires the native command extension policy before this action can execute.",
        }
        .to_owned();
    }
}

/// Tell the user how to restore protection when an unhealthy local authority,
/// not an administrator lockdown, is what blocks every command. Acknowledging
/// a degraded authority keeps the block, so only recovery is suggested.
pub(super) fn add_authority_repair_hint(
    result: &mut PreToolResultV1,
    health: &str,
    global_lockdown: bool,
) {
    if global_lockdown || result.reason_code != "native_command_control_authority_block" {
        return;
    }
    if !matches!(
        health,
        "degraded-unacknowledged" | "degraded-acknowledged" | "tampered" | "recovery-required"
    ) {
        return;
    }
    result.reason.push_str(
        " Run `hol-guard command controls recover-authority` in a terminal to restore protection.",
    );
}
