//! Screens of the prompt, file and program text a tool call carries: a
//! subagent brief admitted only when no prompt detector flags it, file writes
//! that hold a live-looking credential or plant instructions for a later
//! session, and inline programs the read-only sandbox cannot make safe.

use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
use serde_json::Value;

use super::agent_metadata;
use super::extract::GenericSignals;
use super::result::{generic_result, review_reason};

/// A subagent brief is prompt text. Only a brief none of the prompt
/// detectors flag is admitted; the subagent's own tool calls are each
/// checked when it makes them.
pub(super) fn admitted_subagent_brief(
    payload: &Value,
    harness: &str,
    event: &str,
    signals: &GenericSignals,
) -> bool {
    event == "PreToolUse"
        && harness == "claude-code"
        && agent_metadata::subagent_brief(payload, signals.tool_name.as_deref())
        && signals.command.is_none()
        && !signals.package_present
        && !signals.prompt_injection_intent
        && !signals.exfil_intent
        && !signals.destructive_intent
        && !signals.guard_bypass_intent
        && !signals.sensitive_target
}

/// Reviews an allowed file write whose text holds a live-looking credential
/// or an instruction planted for a later agent session.
pub(super) fn review_written_content(
    mut result: PreToolResultV1,
    payload: &Value,
) -> PreToolResultV1 {
    // A key, token or password written into a file leaves the user's hands
    // once the file is committed, synced or read back, so a write that holds
    // a live-looking credential is reviewed rather than allowed as an
    // ordinary workspace edit.
    if result.decision == "allow"
        && result.action.action_type == PreToolActionTypeV1::FileWrite
        && super::super::literal_secrets::writes_literal_secret(payload)
    {
        let (reason_code, _) = review_reason(PreToolActionTypeV1::FileWrite);
        result = generic_result(
        result.action.clone(),
        "review",
        reason_code,
        "This write puts what looks like a real key, token or password into a file. Once the file is committed, synced or read back, the credential is out of your hands.",
    );
    }
    if result.decision == "allow"
        && result.action.action_type == PreToolActionTypeV1::FileWrite
        && super::super::planted_instructions::writes_hidden_instruction(payload)
    {
        let (reason_code, _) = review_reason(PreToolActionTypeV1::FileWrite);
        result = generic_result(
        result.action.clone(),
        "review",
        reason_code,
        "This write leaves an instruction for a later agent session that overrides a safety rule and tells the agent to keep it from you.",
    );
    }
    // Both screens read a bounded prefix of each body, so a body longer than
    // that is reviewed rather than allowed on the strength of its prefix.
    if result.decision == "allow"
        && result.action.action_type == PreToolActionTypeV1::FileWrite
        && super::super::literal_secrets::writes_unscreened_body(payload)
    {
        let (reason_code, _) = review_reason(PreToolActionTypeV1::FileWrite);
        result = generic_result(
        result.action.clone(),
        "review",
        reason_code,
        "This write is too large for Guard to check in full for keys, tokens, passwords or hidden instructions.",
    );
    }
    result
}

/// Keeps the review of a program the read-only evaluation sandbox cannot
/// make safe: it neither hides system files nor stops a child git from
/// discarding the work tree.
pub(super) fn keeps_unsandboxed_program_review(
    result: &mut PreToolResultV1,
    model: &crate::CanonicalCommandV1,
    command_text: Option<&str>,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    crate::pretool::script_content::keeps_system_file_review(result, model, command_text, context)
        || crate::pretool::script_content::keeps_destructive_git_review(
            result,
            model,
            command_text,
            context,
        )
}
