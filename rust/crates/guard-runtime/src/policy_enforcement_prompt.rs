//! A reviewed prompt goes on to the action it leads to.
//!
//! A prompt has no execution binding, so a review held at the prompt could
//! offer neither Allow once nor Always allow (`docs/guard/approval-invariant.md`):
//! the user could only rephrase. A prompt whose effective action is a review
//! is therefore sent with Guard's notice, and the tool call it leads to is
//! reviewed and queued with both choices. Only intents that a later tool call
//! carries out are deferred: reading local secrets, sending data out, deleting
//! files and running subprocesses. A block, a sandbox requirement, a request to
//! switch Guard off, an attempt to override trusted instructions and a prompt
//! with no classified intent still stop the prompt.
//!
//! The deferral accepts two limits. An agent can answer a prompt that asks for
//! a secret from text already in its conversation with no tool call, so no
//! review follows; that text reached the conversation through a reviewed read
//! or the person's own paste, and the reply goes only to the person who asked.
//! A harness with no notice field on a sent prompt (Grok) sends it silently;
//! the tool call it leads to is still reviewed.

use guard_contracts::{NativePromptRiskClassV1, PreToolActionTypeV1, PreToolResultV1};

/// What the harness shows for a prompt Guard flagged and sent.
const PROMPT_REVIEW_NOTICE: &str = "HOL Guard flagged this prompt and sent it. If the agent runs a tool to act on it, Guard asks first; approve that request with Allow once or Always allow if you meant it.";

/// Sends a prompt held only for review, with Guard's notice as its reason.
pub(super) fn defer_prompt_review(output: &mut PreToolResultV1) {
    if output.action.event != "UserPromptSubmit"
        || output.action.action_type != PreToolActionTypeV1::Prompt
        || !matches!(
            output.minimum_action.as_str(),
            "review" | "require-reapproval"
        )
        || output.prompt_risk_classes.is_empty()
        || !output.prompt_risk_classes.iter().all(reaches_a_tool_call)
    {
        return;
    }
    output.policy_action = "warn".to_owned();
    output.minimum_action = "warn".to_owned();
    output.decision = "allow".to_owned();
    output.explicitly_benign = false;
    output.reason = PROMPT_REVIEW_NOTICE.to_owned();
}

/// Whether a later tool call carries out this intent, so its review can wait
/// for that call.
fn reaches_a_tool_call(class: &NativePromptRiskClassV1) -> bool {
    matches!(
        class,
        NativePromptRiskClassV1::LocalEnvRead
            | NativePromptRiskClassV1::SensitiveMaterial
            | NativePromptRiskClassV1::ExfilIntent
            | NativePromptRiskClassV1::DestructiveIntent
            | NativePromptRiskClassV1::SubprocessIntent
    )
}

/// The edge's owned form of [`defer_prompt_review`]. The edge runs it last, so
/// a review held by the native result alone, with no installed policy, or by
/// a runtime risk step after the policy join defers as well.
pub(crate) fn deferred_prompt_review(mut output: PreToolResultV1) -> PreToolResultV1 {
    defer_prompt_review(&mut output);
    output
}

#[cfg(test)]
#[path = "policy_enforcement_prompt_tests.rs"]
mod tests;
