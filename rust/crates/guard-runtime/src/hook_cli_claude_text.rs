//! Claude Code approval copy the in-process `guard hook` command writes.
//!
//! The daemon path already renders its Claude replies from
//! `hook_direct::claude_permission_text`. The CLI path kept its own copy of
//! that text in `commands_support_claude_approval`, so the two could drift.
//! These functions are the CLI's side of the same text: the terminal notices
//! it writes to stderr and the model context it attaches, built from the same
//! tool-name and punctuation helpers the daemon uses.

use serde_json::{Map, Value};

use crate::hook_direct::claude_permission_text::{
    ensure_terminal_punctuation, guard_approval_question_message, notice_field,
    notice_prefers_ask_user_question, notification_tool_display_name, notification_tool_name,
    permission_prompt_additional_context, permission_prompt_system_message,
    permission_request_system_message,
};

/// `_claude_permission_request_terminal_notice`.
fn permission_request_terminal_notice(payload: &Map<String, Value>, native_reason: &str) -> String {
    let reason = ensure_terminal_punctuation(native_reason);
    match notification_tool_display_name(payload) {
        Some(name) => format!("HOL Guard: reviewing Claude approval for {name}. {reason}"),
        None => format!("HOL Guard: reviewing this Claude approval prompt. {reason}"),
    }
}

/// `_claude_permission_request_additional_context`.
fn permission_request_additional_context(native_reason: &str) -> String {
    format!(
        "This review came from HOL Guard, not from Claude alone. {} \
         Use Claude's normal Allow / deny controls unless HOL Guard opened a separate approval question.",
        ensure_terminal_punctuation(native_reason)
    )
}

/// `_claude_permission_prompt_terminal_notice`.
fn permission_prompt_terminal_notice(
    payload: &Map<String, Value>,
    notice: Option<&Map<String, Value>>,
) -> String {
    let tool_name = notification_tool_name(payload);
    let reason = notice_field(notice, "reason");
    match (tool_name, reason) {
        (Some(name), Some(reason)) => format!(
            "HOL Guard is routing this Claude approval request for {name} into a HOL Guard decision \
             prompt. {} Choose Allow once, Allow during this session, or Keep blocked in the HOL \
             Guard prompt.",
            ensure_terminal_punctuation(reason)
        ),
        (Some(name), None) => format!(
            "HOL Guard is routing this Claude approval request for {name} into a HOL Guard decision \
             prompt. Choose Allow once, Allow during this session, or Keep blocked in the HOL Guard \
             prompt."
        ),
        (None, _) => "HOL Guard is routing this Claude approval request into a HOL Guard decision \
                      prompt to protect a sensitive action. Choose Allow once, Allow during this \
                      session, or Keep blocked in the HOL Guard prompt."
            .to_owned(),
    }
}

/// `_claude_native_pretooluse_terminal_notice`.
fn native_pretooluse_terminal_notice(payload: &Map<String, Value>, reason: &str) -> String {
    let reason = ensure_terminal_punctuation(reason);
    match notification_tool_name(payload) {
        Some(name) => format!(
            "HOL Guard intercepted Claude's attempt to use {name}. {reason} Guard will route the \
             next approval through a HOL Guard prompt if Claude asks to continue."
        ),
        None => format!(
            "HOL Guard intercepted a sensitive Claude action. {reason} Guard will route the next \
             approval through a HOL Guard prompt if Claude asks to continue."
        ),
    }
}

/// One named piece of Claude approval copy, or `None` for an unknown name.
///
/// `payload` is the hook payload the CLI read off the wire, `notice` the
/// pending Guard notice the CLI peeked (absent when there is none) and
/// `reason` the composed native reason.
pub(crate) fn claude_approval_copy(
    which: &str,
    payload: &Map<String, Value>,
    notice: Option<&Map<String, Value>>,
    reason: &str,
) -> Option<Value> {
    let text = match which {
        "approval_question_message" => guard_approval_question_message(notice),
        "permission_request_terminal_notice" => permission_request_terminal_notice(payload, reason),
        "permission_request_system_message" => permission_request_system_message(payload, reason),
        "permission_request_additional_context" => permission_request_additional_context(reason),
        "permission_prompt_system_message" => permission_prompt_system_message(payload, notice),
        "permission_prompt_additional_context" => permission_prompt_additional_context(notice),
        "permission_prompt_terminal_notice" => permission_prompt_terminal_notice(payload, notice),
        "native_pretooluse_terminal_notice" => native_pretooluse_terminal_notice(payload, reason),
        "notice_prefers_ask_user_question" => {
            return Some(Value::Bool(
                notice.is_some_and(notice_prefers_ask_user_question),
            ))
        }
        _ => return None,
    };
    Some(Value::String(text))
}

#[cfg(test)]
#[path = "hook_cli_claude_text_tests.rs"]
mod tests;
