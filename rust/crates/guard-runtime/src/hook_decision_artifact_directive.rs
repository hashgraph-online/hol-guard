//! `HookDecide` `artifact_directive` — the artifact hook's response directive.
//!
//! The artifact hook's verdict is settled before it is rendered; this picks
//! how: the exit block or the rendered response, the emitter, which reason
//! and system message the harness is shown, and the exit code. The transport
//! renders the directive and decides nothing itself.

use guard_contracts::{ArtifactDirectiveInputsV1, GuardAction, HookResponseDirectiveV1};

use crate::hook_decision_directive::{
    emitter, exit_block, exit_code, is_blocking, native_response, DirectiveFacts,
};
use crate::hook_decision_finalize::parse_action;

/// The Claude system message for a prompt or tool call, by kind.
pub(crate) fn claude_system_message(
    event: &str,
    prompt_hard_block: bool,
    prompt_secret_read: bool,
    action: GuardAction,
) -> &'static str {
    let stops = matches!(action, GuardAction::Block | GuardAction::SandboxRequired);
    match event {
        "UserPromptSubmit" => {
            if action == GuardAction::RequireReapproval && !prompt_hard_block {
                // A sensitive prompt may still be approved; say why it paused.
                if prompt_secret_read {
                    "claude_prompt_secret"
                } else {
                    "claude_prompt_sensitive"
                }
            } else if stops {
                "claude_punctuated"
            } else {
                "none"
            }
        }
        "PreToolUse" if stops || action == GuardAction::RequireReapproval => "claude_punctuated",
        _ => "none",
    }
}

fn system_message(inputs: &ArtifactDirectiveInputsV1, action: GuardAction) -> &'static str {
    match inputs.canonical_harness.as_str() {
        "claude-code" => claude_system_message(
            &inputs.event,
            inputs.prompt_hard_block,
            inputs.prompt_secret_read,
            action,
        ),
        "codex" if inputs.event == "UserPromptSubmit" && is_blocking(action) => "codex_prompt",
        _ => "none",
    }
}

/// Codex quotes the approval context (or else the review hint) for prompts,
/// approvals and hard stops; every other reason is the harness's own.
fn codex_native_reason(inputs: &ArtifactDirectiveInputsV1, action: GuardAction) -> &'static str {
    let quoted = inputs.event == "UserPromptSubmit"
        || inputs.approval_context_present
        || matches!(action, GuardAction::Block | GuardAction::SandboxRequired);
    if inputs.canonical_harness == "codex" && quoted {
        "artifact_codex"
    } else {
        "never"
    }
}

pub(crate) fn artifact_directive(
    inputs: &ArtifactDirectiveInputsV1,
) -> Result<HookResponseDirectiveV1, String> {
    let action = parse_action(&inputs.policy_action)?;
    let canonical = inputs.canonical_harness.as_str();
    let event = inputs.event.as_str();
    let facts = DirectiveFacts {
        harness: &inputs.harness,
        canonical,
        event,
        action,
        observed: false,
        observe_mode: false,
        has_approval_requests_list: false,
        json: inputs.json,
        output_stream_present: inputs.output_stream_present,
        replayed: inputs.replayed,
    };
    let blocking = is_blocking(action);
    let ask = matches!(action, GuardAction::Review | GuardAction::RequireReapproval);
    let exit_block = exit_block(&facts);
    let after_json = if native_response(&facts) {
        "native_response"
    } else if event == "PostToolUse" {
        "post_tool_envelope"
    } else {
        "fallback_envelope"
    };
    let mut exit = exit_code(canonical, action, event);
    if !exit_block && after_json == "fallback_envelope" && inputs.replayed {
        // A replayed decision was recorded upstream; acknowledge without
        // re-blocking the harness.
        exit = Some(0);
    }
    Ok(HookResponseDirectiveV1 {
        route: if exit_block { "exit_block" } else { "render" }.to_owned(),
        queue_observe_request: false,
        queue_approval_request: false,
        emitter: emitter(canonical).to_owned(),
        exit_code: exit,
        stderr_only_on_nonzero_exit: false,
        codex_native_reason: codex_native_reason(inputs, action).to_owned(),
        include_remediation: blocking,
        terminal_notice: !exit_block && canonical == "claude-code" && event == "PreToolUse" && ask,
        system_message: system_message(inputs, action).to_owned(),
        try_json_document: inputs.json && !inputs.output_stream_present,
        after_json: after_json.to_owned(),
        envelope_decision: if blocking { "block" } else { "allow" }.to_owned(),
        // Grok's adapter owns its blocking exit and writes no stderr.
        exit_block_stderr: Some(canonical != "grok"),
        json_reason: Some(
            if canonical == "copilot" {
                "copilot"
            } else {
                "harness"
            }
            .to_owned(),
        ),
    })
}

#[cfg(test)]
#[path = "hook_decision_artifact_directive_tests.rs"]
mod tests;
