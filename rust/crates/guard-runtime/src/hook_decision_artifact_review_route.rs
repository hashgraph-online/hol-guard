//! `HookDecide` `artifact_review_route` — the artifact hook's review route.
//!
//! Once the artifact hook has settled a verdict, a review-tier or terminal
//! action still has to go somewhere: stored as a silent denial, recorded as
//! observed, answered natively, or queued for approval. This picks the branch.
//! The transport gathers the facts, runs the branch it is told to, and decides
//! nothing itself.
//!
//! The approval invariant holds here: a `review` or `require-reapproval`
//! verdict is closed as a silent denial only when blocked requests are not
//! offered for approval (and the harness is not merely observing); it is never
//! terminalized, and every other route leaves it offered as Allow once and
//! Always allow. A prompt that asks to bypass Guard is the one review-tier
//! verdict that is not queued, because it is not an executable action.

use guard_contracts::{
    ArtifactReviewRouteInputsV1, ArtifactReviewRouteV1, GuardAction, HookSilentReviewV1,
};

use crate::hook_decision_artifact_directive::claude_system_message;
use crate::hook_decision_finalize::parse_action;

/// What the agent is told first when a review is closed without a prompt.
const SILENT_LEAD: &str = "HOL Guard blocked this action.";

fn route(name: &str) -> ArtifactReviewRouteV1 {
    ArtifactReviewRouteV1 {
        route: name.to_owned(),
        terminalize: "none".to_owned(),
        record_claude_notice: false,
        attach_cursor_request_ids: false,
        system_message: "none".to_owned(),
        additional_context: "none".to_owned(),
        silent_review: None,
    }
}

/// Claude answers the hook itself, before anything is queued, unless `--json`
/// asks for the composed envelope. A prompt submit keeps that envelope under
/// `--json`; a tool call answers natively only into a caller-owned stream.
fn claude_answers_natively(inputs: &ArtifactReviewRouteInputsV1) -> bool {
    if inputs.canonical_harness != "claude-code" {
        return false;
    }
    if !inputs.json {
        return true;
    }
    inputs.event != "UserPromptSubmit" && inputs.output_stream_present
}

pub(crate) fn artifact_review_route(
    inputs: &ArtifactReviewRouteInputsV1,
) -> Result<ArtifactReviewRouteV1, String> {
    let action = parse_action(&inputs.policy_action)?;
    let review_tier = matches!(action, GuardAction::Review | GuardAction::RequireReapproval);
    let terminal = matches!(action, GuardAction::Block | GuardAction::SandboxRequired);
    if !review_tier && !terminal {
        return Ok(route("continue"));
    }
    let observing = inputs.observe_mode;
    // Cursor's native prompt covers exactly the review tier, so it adds no
    // case of its own: a review-tier verdict is silent or it is not.
    if !observing && !inputs.asks_for_approval && (review_tier || action == GuardAction::Block) {
        let mut silent = route(if review_tier {
            "silent_review"
        } else {
            "silent_block"
        });
        silent.silent_review = Some(HookSilentReviewV1 {
            action: action.as_str().to_owned(),
            reason: SILENT_LEAD.to_owned(),
        });
        return Ok(silent);
    }
    let mut chosen = route("continue");
    if terminal {
        chosen.terminalize = if observing { "observe" } else { "enforce" }.to_owned();
    }
    if observing {
        chosen.route = "observe".to_owned();
        return Ok(chosen);
    }
    let event = inputs.event.as_str();
    chosen.record_claude_notice =
        inputs.canonical_harness == "claude-code" && event == "PreToolUse" && review_tier;
    if inputs.harness == "copilot" && !inputs.json {
        chosen.route = "copilot_response".to_owned();
    } else if claude_answers_natively(inputs) {
        chosen.route = "native_response".to_owned();
        let message = claude_system_message(
            event,
            inputs.prompt_hard_block,
            inputs.prompt_secret_read,
            action,
        );
        chosen.system_message = message.to_owned();
        if message.starts_with("claude_prompt_") {
            chosen.additional_context = message.to_owned();
        }
    } else if review_tier && !inputs.prompt_hard_block {
        chosen.route = "queue_approval".to_owned();
        chosen.attach_cursor_request_ids = inputs.canonical_harness == "cursor"
            && event == "PreToolUse"
            && inputs.artifact_type == "tool_action_request";
    }
    Ok(chosen)
}

#[cfg(test)]
#[path = "hook_decision_artifact_review_route_tests.rs"]
mod tests;
