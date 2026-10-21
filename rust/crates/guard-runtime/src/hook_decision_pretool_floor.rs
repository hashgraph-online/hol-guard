//! `HookDecide` `pretool_floor` — the action a PreToolUse verdict is held at.
//!
//! The resident pre-tool review returns a `minimum_action` for the command.
//! This decides whether it floors the hook verdict: every canonical action
//! does, `sandbox-required` included, so the floor keeps that tier instead of
//! collapsing it to a block. The floor only enters the policy actions: the
//! containment rewrite itself is routed from the edge result. A contextual
//! git-helper review is the one answer that does not, because the hook settles
//! it from facts the review does not see.
//!
//! The approval invariant holds here: a `review` floor stays `review`, the
//! tier whose card offers Allow once and Always allow; nothing is raised to a
//! terminal action. A malformed answer is an error the transport reports as a
//! resident outage, never a default floor.

use guard_contracts::{GuardAction, PretoolFloorInputsV1, PretoolFloorV1};

/// The review the hook settles from its own context, not a floor.
const CONTEXTUAL_GIT_HELPER_REVIEW: &str = "native_git_helper_context_review";

pub(crate) fn pretool_floor(inputs: &PretoolFloorInputsV1) -> Result<PretoolFloorV1, String> {
    let action = GuardAction::from_canonical(&inputs.minimum_action)
        .ok_or_else(|| "native_hook_decision_action_invalid".to_owned())?;
    if inputs.reason_code.is_empty() {
        return Err("native_hook_decision_payload_invalid".to_owned());
    }
    if action == GuardAction::Review && inputs.reason_code == CONTEXTUAL_GIT_HELPER_REVIEW {
        return Ok(PretoolFloorV1 { floor: None });
    }
    Ok(PretoolFloorV1 {
        floor: Some(action.as_str().to_owned()),
    })
}

#[cfg(test)]
#[path = "hook_decision_pretool_floor_tests.rs"]
mod tests;
