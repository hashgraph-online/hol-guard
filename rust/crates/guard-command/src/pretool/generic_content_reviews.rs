//! Screens of the prompt, file and program text a tool call carries: a
//! subagent brief admitted only when no prompt detector flags it, file writes
//! that hold a live-looking credential or plant instructions for a later
//! session, and inline programs the read-only sandbox cannot make safe.

use std::borrow::Cow;

use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
use serde_json::{Map, Value};

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

/// Every argument object a call carries: `tool_input` and each alias the
/// signal extractor also reads (`toolInput`, `arguments`, ...), sent as an
/// object or as JSON-encoded text. The flag is set when JSON-looking argument
/// text could not be read, so its body went unscreened.
fn argument_inputs(payload: &Value) -> (Vec<Cow<'_, Map<String, Value>>>, bool) {
    let mut inputs = Vec::new();
    let mut unparsed = false;
    let Some(root) = payload.as_object() else {
        return (inputs, unparsed);
    };
    for key in super::extract::EMBEDDED_ARGUMENT_KEYS {
        match root.get(key) {
            Some(Value::Object(input)) => inputs.push(Cow::Borrowed(input)),
            Some(Value::String(text)) if text.trim_start().starts_with('{') => {
                match super::extract::parse_strict_nested_json(text.trim().as_bytes()) {
                    Ok(Value::Object(input)) => inputs.push(Cow::Owned(input)),
                    _ => unparsed = true,
                }
            }
            _ => {}
        }
    }
    (inputs, unparsed)
}

/// Reviews an allowed file write whose text holds a live-looking credential
/// or an instruction planted for a later agent session.
pub(super) fn review_written_content(
    mut result: PreToolResultV1,
    payload: &Value,
) -> PreToolResultV1 {
    let (inputs, unparsed) = argument_inputs(payload);
    let cwd = payload.get("cwd").and_then(Value::as_str);
    // A key, token or password written into a file leaves the user's hands
    // once the file is committed, synced or read back, so a write that holds
    // a live-looking credential is reviewed rather than allowed as an
    // ordinary workspace edit.
    if result.decision == "allow"
        && result.action.action_type == PreToolActionTypeV1::FileWrite
        && inputs
            .iter()
            .any(|input| super::super::literal_secrets::writes_literal_secret(input))
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
        && inputs
            .iter()
            .any(|input| super::super::planted_instructions::writes_hidden_instruction(input))
    {
        let (reason_code, _) = review_reason(PreToolActionTypeV1::FileWrite);
        result = generic_result(
        result.action.clone(),
        "review",
        reason_code,
        "This write leaves an instruction for a later agent session that overrides a safety rule and tells the agent to keep it from you.",
    );
    }
    if result.decision == "allow"
        && result.action.action_type == PreToolActionTypeV1::FileWrite
        && inputs
            .iter()
            .any(|input| super::super::install_script_writes::adds_install_script(input, cwd))
    {
        let (reason_code, _) = review_reason(PreToolActionTypeV1::FileWrite);
        result = generic_result(
        result.action.clone(),
        "review",
        reason_code,
        "This write adds an install script to package.json. The package manager runs it on every later install, on this machine and on anyone else's, without asking.",
    );
    }
    // Both screens read a bounded prefix of each body, so a body longer than
    // that is reviewed rather than allowed on the strength of its prefix.
    if result.decision == "allow"
        && result.action.action_type == PreToolActionTypeV1::FileWrite
        && (unparsed
            || inputs
                .iter()
                .any(|input| super::super::literal_secrets::writes_unscreened_body(input)))
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
        || keeps_hook_neutering_review(result, model, command_text)
}

/// Keeps the review of a command that overwrites a git hook with a script
/// that does nothing, or renames a hook away. The sandbox writes anywhere
/// in the workspace, so the hook stays switched off after the run ends.
fn keeps_hook_neutering_review(
    result: &mut PreToolResultV1,
    model: &crate::CanonicalCommandV1,
    command_text: Option<&str>,
) -> bool {
    if !crate::pretool::hook_neutering::neuters_git_hooks(&model.normalized_text)
        && !command_text.is_some_and(crate::pretool::hook_neutering::neuters_git_hooks)
    {
        return false;
    }
    result.reason = concat!(
        "HOL Guard needs your review because this command switches off a git hook ",
        "for every later commit, which Guard's sandbox does not undo."
    )
    .into();
    true
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::argument_inputs;

    #[test]
    fn every_argument_alias_is_read_and_unreadable_json_is_flagged() {
        let payload = json!({
            "toolInput": {"file_path": "/w/a.py", "content": "a"},
            "arguments": "{\"file_path\": \"/w/b.py\", \"content\": \"b\"}"
        });
        let (inputs, unparsed) = argument_inputs(&payload);
        assert_eq!(inputs.len(), 2);
        assert!(!unparsed);
        let (_, unparsed) = argument_inputs(&json!({"tool_args": "{\"content\": "}));
        assert!(unparsed);
    }
}
