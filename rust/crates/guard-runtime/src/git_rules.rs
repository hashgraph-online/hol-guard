//! The user's own git rules at the hook edge.
//!
//! Two rules a user can turn on, each with its own risk setting:
//!
//! * `git_hook_bypass`: never skip, switch off or redirect the hooks that run
//!   before a commit or push (`--no-verify`, `HUSKY=0`, an empty
//!   `core.hooksPath`);
//! * `git_stage_all`: stage files by name, never the whole tree (`git add .`,
//!   `git add -A`, `git stage -A` under Git's second name for the same
//!   builtin, `git commit -a`).
//!
//! Every preset leaves both at `allow`, so nothing changes until the user
//! sets one. A command that breaks a rule the user set is raised to that
//! rule's action, with Allow once and Always allow on the review like any
//! other. Watch mode records the would-be decision as a warning. A sandbox
//! route does not stop either effect, so a rule the user set to review holds
//! a command that would otherwise run in the sandbox. A block stays a block.

use guard_contracts::{GuardHookEnvelopeV2, PreToolActionTypeV1, PreToolResultV1};

use crate::git_rules_match::breaks;
use crate::policy_enforcement::{risk_action, ActionFloor, AdmittedPolicySnapshot};

const HOOK_BYPASS_KEY: &str = "git_hook_bypass";
const STAGE_ALL_KEY: &str = "git_stage_all";
const HOOK_BYPASS: &str = "native_git_hook_bypass";
const STAGE_ALL: &str = "native_git_stage_all";
const HOOK_BYPASS_OBSERVED: &str = "native_git_hook_bypass_observed";
const STAGE_ALL_OBSERVED: &str = "native_git_stage_all_observed";

/// Whether `reason_code` is a review this overlay holds before execution.
pub(crate) fn is_review_finding(reason_code: &str) -> bool {
    matches!(reason_code, HOOK_BYPASS | STAGE_ALL)
}

/// One broken rule and the action the user set for it.
struct Rule {
    action: String,
    code: &'static str,
    observed: &'static str,
    reason: &'static str,
}

/// Exact-command review, then the user's git rules on its result.
pub(crate) fn after_exact_review(
    envelope: &GuardHookEnvelopeV2,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    let result =
        crate::edge_exact_command_review::apply_to_envelope(envelope, policy_snapshot, result);
    apply(envelope, policy_snapshot, result)
}

pub(crate) fn apply(
    envelope: &GuardHookEnvelopeV2,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    let Some(snapshot) = policy_snapshot else {
        return result;
    };
    if result.minimum_action == "block"
        || result.action.event != "PreToolUse"
        || !shell_action(&result.action.action_type)
    {
        return result;
    }
    let set = |key: &str| match risk_action(snapshot, &result.action.harness, key) {
        Ok(Some(action)) if action != "allow" => Some(action),
        _ => None,
    };
    let (hook_action, stage_action) = (set(HOOK_BYPASS_KEY), set(STAGE_ALL_KEY));
    if hook_action.is_none() && stage_action.is_none() {
        return result;
    }
    let Some(command) = crate::runtime_known_vulnerable::command_text(&envelope.raw_payload) else {
        return result;
    };
    let cwd = envelope.source.cwd.as_deref().map(std::path::Path::new);
    let found = breaks(&command, cwd);
    let mut rules = Vec::new();
    if let Some(action) = hook_action.filter(|_| found.hook_bypass) {
        rules.push(Rule {
            action,
            code: HOOK_BYPASS,
            observed: HOOK_BYPASS_OBSERVED,
            reason: "Your git rules say never to skip or switch off the hooks that run before a \
                     commit or push, and this command does.",
        });
    }
    if let Some(action) = stage_action.filter(|_| found.stage_all) {
        rules.push(Rule {
            action,
            code: STAGE_ALL,
            observed: STAGE_ALL_OBSERVED,
            reason: "Your git rules say to stage files by name, and this command stages the \
                     whole working tree.",
        });
    }
    // The strictest rule decides; ties keep the first.
    let strictest = rules.into_iter().reduce(|kept, next| {
        if ActionFloor::parse(&next.action) > ActionFloor::parse(&kept.action) {
            next
        } else {
            kept
        }
    });
    match strictest {
        Some(rule) => raise(result, &rule, snapshot.mode == "observe"),
        None => result,
    }
}

/// Whether a call of this type runs a shell command. A command that also
/// runs a package script, starts a service or reaches the network is typed
/// by that step, and its git steps still run.
fn shell_action(action_type: &PreToolActionTypeV1) -> bool {
    matches!(
        action_type,
        PreToolActionTypeV1::Command
            | PreToolActionTypeV1::Package
            | PreToolActionTypeV1::ProcessService
            | PreToolActionTypeV1::Network
    )
}

fn raise(mut result: PreToolResultV1, rule: &Rule, observe: bool) -> PreToolResultV1 {
    let (Some(minimum), Some(policy), Some(configured)) = (
        ActionFloor::parse(&result.minimum_action),
        ActionFloor::parse(&result.policy_action),
        ActionFloor::parse(&rule.action),
    ) else {
        return result;
    };
    if observe || configured <= ActionFloor::Warn {
        let note = if configured > ActionFloor::Warn {
            format!("{} Guard would have required {}.", rule.reason, rule.action)
        } else {
            rule.reason.into()
        };
        if minimum == ActionFloor::Warn && result.decision == "allow" {
            // Keep the warning already given and add this rule's finding.
            if !result.reason.contains(rule.reason) {
                result.reason = format!("{} {note}", result.reason).trim().into();
            }
        } else if minimum < ActionFloor::Warn {
            result.minimum_action = "warn".into();
            if policy < ActionFloor::Warn {
                result.policy_action = "warn".into();
            }
            result.decision = "allow".into();
            result.explicitly_benign = false;
            result.reason_code = rule.observed.into();
            result.reason = note;
        }
        return result;
    }
    // A sandbox lets the command run, and running it is the harm here: the
    // commit still lands and the hooks still do not run. The route can come
    // from the floor or from the user's posture alone, as when a package
    // script beside the git step is contained under a review floor. Approving
    // the review settles it the way any saved grant settles a sandbox route.
    let sandbox = ActionFloor::SandboxRequired;
    let sandboxed = (minimum == sandbox || policy == sandbox) && configured < ActionFloor::Block;
    if minimum >= configured && !sandboxed {
        return result;
    }
    let lifted = |floor: ActionFloor| {
        if floor == sandbox {
            configured
        } else {
            floor.max(configured)
        }
    };
    let minimum = lifted(minimum);
    result.minimum_action = floor_name(minimum).into();
    result.policy_action = floor_name(lifted(policy).max(minimum)).into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    result.reason_code = rule.code.into();
    result.reason = rule.reason.into();
    result
}

fn floor_name(floor: ActionFloor) -> &'static str {
    match floor {
        ActionFloor::Allow => "allow",
        ActionFloor::Warn => "warn",
        ActionFloor::Review => "review",
        ActionFloor::RequireReapproval => "require-reapproval",
        ActionFloor::SandboxRequired => "sandbox-required",
        ActionFloor::Block => "block",
    }
}

#[cfg(test)]
#[path = "git_rules_tests.rs"]
mod tests;
