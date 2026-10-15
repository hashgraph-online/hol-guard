//! Claude Code `PermissionRequest` copy the resident answers with.
//!
//! Claude raises `PermissionRequest` only after `PreToolUse` let the call
//! continue. The daemon's `claude_permission_request_response` peeks the
//! pending Guard notice, marks it seen and builds the reply from the helpers
//! in `commands_support_claude_approval`. These functions repeat that reply
//! text exactly; the caller does the peek and the mark-seen. A notice that
//! expects an explicit answer denies Claude's dialog and directs Claude to
//! the Guard approval question; any other notice shows its review reason and
//! defers to Claude's dialog.

use guard_command::workspace_inventory::python_strip;
use serde_json::{json, Map, Value};

use crate::guard_config_coerce::python_truthy;
use crate::guard_store_json::{dumps_default, py_str};

/// `CLAUDE_GUARD_PERMISSION_PASSTHROUGH_KEY`: Claude keeps its own dialog.
pub(super) const PERMISSION_PASSTHROUGH_KEY: &str = "guard_permission_passthrough";
/// `_CLAUDE_GUARD_APPROVAL_HEADER`.
const APPROVAL_HEADER: &str = "HOL Guard";
/// `_CLAUDE_GUARD_APPROVAL_OPTIONS`.
const APPROVAL_OPTIONS: [&str; 3] = ["Allow once", "Allow during this session", "Keep blocked"];
const DEFAULT_APPROVAL_QUESTION: &str =
    "HOL Guard intercepted this sensitive action. What should Claude do?";
/// The reason shown when a deferring notice carries none.
const DEFAULT_REVIEW_REASON: &str = "HOL Guard requires review before this action can execute.";
const PERMISSION_REQUEST: &str = "PermissionRequest";
const NOTIFICATION: &str = "Notification";
/// The event the daemon records for every Claude permission prompt.
pub(super) const PERMISSION_PROMPT_EVENT: &str = "claude/permission_prompt";
const DEFAULT_PROMPT_CONTEXT: &str =
    "HOL Guard intercepted the sensitive request and is routing it \
     into a HOL Guard approval question. This approval flow came from HOL Guard, not from Claude \
     alone. Ask the user with AskUserQuestion and the options Allow once, Allow during this \
     session, and Keep blocked. If the user chooses Keep blocked, do not retry the same action.";

/// `_optional_string`: a string that is not blank, stripped.
fn optional_string(value: Option<&Value>) -> Option<&str> {
    let stripped = python_strip(value?.as_str()?);
    (!stripped.is_empty()).then_some(stripped)
}

/// `_optional_string` of a notice field; no notice reads as `{}`.
fn notice_field<'a>(notice: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a str> {
    optional_string(notice?.get(key))
}

/// `ensure_terminal_punctuation`: stripped, ending in `.`, `!` or `?`.
pub(super) fn ensure_terminal_punctuation(message: &str) -> String {
    let trimmed = python_strip(message);
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with(['.', '!', '?']) {
        return trimmed.to_owned();
    }
    format!("{trimmed}.")
}

/// A character `re`'s `\s` matches in a `str` pattern (`str.isspace`).
fn is_python_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// A character `re`'s `\b` counts as a word character in a `str` pattern
/// (`str.isalnum` or `_`).
fn is_python_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// The first group of `re.search(r"\buse\s+([A-Za-z][A-Za-z0-9_]*)\b", text)`.
///
/// Neither `\s+` nor the greedy name can give back a character and still
/// match, so each `use` candidate either matches at full width or fails.
fn use_tool_name(text: &str) -> Option<&str> {
    let characters: Vec<(usize, char)> = text.char_indices().collect();
    let at = |index: usize| characters.get(index).map(|(_, character)| *character);
    for start in 0..characters.len() {
        if start > 0 && at(start - 1).is_some_and(is_python_word) {
            continue;
        }
        if at(start) != Some('u') || at(start + 1) != Some('s') || at(start + 2) != Some('e') {
            continue;
        }
        let mut index = start + 3;
        while at(index).is_some_and(is_python_space) {
            index += 1;
        }
        if index == start + 3 || !at(index).is_some_and(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let name_start = index;
        index += 1;
        while at(index).is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            index += 1;
        }
        if at(index).is_some_and(is_python_word) {
            continue;
        }
        let begin = characters[name_start].0;
        let end = characters
            .get(index)
            .map_or(text.len(), |(offset, _)| *offset);
        return Some(&text[begin..end]);
    }
    None
}

/// `_claude_notification_tool_name`: the payload's tool name, else the tool
/// a `message` or `title` names as `use <Tool>`.
pub(super) fn notification_tool_name(payload: &Map<String, Value>) -> Option<String> {
    if let Some(direct) = optional_string(payload.get("tool_name")) {
        return Some(direct.to_owned());
    }
    ["message", "title"]
        .into_iter()
        .filter_map(|key| optional_string(payload.get(key)))
        .find_map(use_tool_name)
        .map(str::to_owned)
}

/// `_claude_notification_tool_display_name`.
pub(super) fn notification_tool_display_name(payload: &Map<String, Value>) -> Option<String> {
    let name = notification_tool_name(payload)?;
    let stripped = python_strip(&name);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// `_claude_guard_approval_options_from_value`: every label, or none when
/// the value is not a list or any item has no label. A string item is only
/// stripped, so a blank one still counts.
fn approval_options(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut labels = Vec::with_capacity(items.len());
    for item in items {
        let label = match item {
            Value::Object(fields) => optional_string(fields.get("label")),
            Value::String(text) => Some(python_strip(text)),
            _ => None,
        };
        let Some(label) = label else {
            return Vec::new();
        };
        labels.push(label.to_owned());
    }
    labels
}

/// `_claude_guard_approval_question_message`: the deny message that directs
/// Claude to ask the Guard approval question.
pub(super) fn guard_approval_question_message(notice: Option<&Map<String, Value>>) -> String {
    let field = |key: &str| notice_field(notice, key);
    let tool_name = field("tool_name").unwrap_or("this tool");
    let header = field("approval_header").unwrap_or(APPROVAL_HEADER);
    let question = field("approval_question").unwrap_or(DEFAULT_APPROVAL_QUESTION);
    let mut options = approval_options(notice.and_then(|fields| fields.get("approval_options")));
    if options.is_empty() {
        options = APPROVAL_OPTIONS.into_iter().map(String::from).collect();
    }
    let options_text = options.join("', '");
    let reason_text = field("reason").map_or_else(String::new, |reason| {
        format!(" HOL Guard reason: {}", ensure_terminal_punctuation(reason))
    });
    format!(
        "HOL Guard needs the user's explicit decision before {tool_name} can run.{reason_text} \
         The native Claude permission prompt is not the final decision surface for this request. Call \
         AskUserQuestion now with one HOL Guard approval question before retrying the tool. Use header \
         '{header}', question '{question}', and exactly these options: '{options_text}'. If the user chooses an \
         allow option, retry the same tool once. If the user chooses Keep blocked, do not retry the sensitive action."
    )
}

/// `_claude_permission_notice_prefers_ask_user_question`: every notice but a
/// package request expects the Guard approval question.
pub(super) fn notice_prefers_ask_user_question(notice: &Map<String, Value>) -> bool {
    optional_string(notice.get("artifact_type")) != Some("package_request")
}

/// `_claude_permission_prompt_system_message`: what the user sees while
/// Claude is sent to the Guard approval question.
pub(super) fn permission_prompt_system_message(
    payload: &Map<String, Value>,
    notice: Option<&Map<String, Value>>,
) -> String {
    let tool_name = notification_tool_name(payload)
        .or_else(|| notice_field(notice, "tool_name").map(str::to_owned));
    let intro = tool_name.map_or_else(
        || {
            "HOL Guard intercepted a sensitive request and is routing it to a HOL Guard approval \
             question."
                .to_owned()
        },
        |name| {
            format!(
                "HOL Guard intercepted Claude's attempt to use {name} and is routing it to a HOL \
                 Guard approval question."
            )
        },
    );
    match notice_field(notice, "reason") {
        Some(reason) => format!(
            "{intro} This approval flow came from HOL Guard, not from Claude alone. {} \
             HOL Guard will ask the user to choose Allow once, Allow during this session, or Keep \
             blocked before Claude retries the action.",
            ensure_terminal_punctuation(reason)
        ),
        None => format!(
            "{intro} This approval flow came from HOL Guard, not from Claude alone. HOL Guard will \
             ask the user to choose Allow once, Allow during this session, or Keep blocked before \
             Claude retries the action."
        ),
    }
}

/// `_claude_permission_request_system_message`: the review reason shown
/// above Claude's own dialog.
pub(super) fn permission_request_system_message(
    payload: &Map<String, Value>,
    native_reason: &str,
) -> String {
    let reason = ensure_terminal_punctuation(native_reason);
    match notification_tool_display_name(payload) {
        Some(name) => format!(
            "HOL Guard is reviewing Claude's approval prompt for {name}. Claude's risk warnings \
             above are separate from HOL Guard. {reason}"
        ),
        None => format!(
            "HOL Guard is reviewing this Claude approval prompt. Claude's risk warnings above are \
             separate from HOL Guard. {reason}"
        ),
    }
}

/// `str(notice.get("reason") or <default>)`: a falsy reason falls back, and
/// any other JSON value is rendered as Python's `str` renders it.
pub(super) fn permission_request_reason(notice: &Map<String, Value>) -> String {
    match notice.get("reason") {
        Some(reason) if python_truthy(Some(reason)) => {
            py_str(reason).unwrap_or_else(|| DEFAULT_REVIEW_REASON.to_owned())
        }
        _ => DEFAULT_REVIEW_REASON.to_owned(),
    }
}

/// `claude_permission_request_response` once the caller has peeked the
/// pending notice (and, when there is one, marked it seen).
pub(super) fn permission_request_response(
    payload: &Map<String, Value>,
    notice: Option<&Map<String, Value>>,
) -> Value {
    let Some(notice) = notice else {
        return json!({
            PERMISSION_PASSTHROUGH_KEY: true,
            "hookSpecificOutput": {"hookEventName": PERMISSION_REQUEST},
        });
    };
    if notice_prefers_ask_user_question(notice) {
        return json!({
            "systemMessage": permission_prompt_system_message(payload, Some(notice)),
            "hookSpecificOutput": {
                "hookEventName": PERMISSION_REQUEST,
                "decision": {
                    "behavior": "deny",
                    "message": guard_approval_question_message(Some(notice)),
                    "interrupt": false,
                },
            },
        });
    }
    // PermissionRequest has no model-context field; the user sees the reason.
    let reason = permission_request_reason(notice);
    json!({
        PERMISSION_PASSTHROUGH_KEY: true,
        "hookSpecificOutput": {"hookEventName": PERMISSION_REQUEST},
        "systemMessage": permission_request_system_message(payload, &reason),
    })
}

/// `_claude_permission_prompt_additional_context`: the notice's Guard
/// approval question, or the generic routing note without a notice.
pub(super) fn permission_prompt_additional_context(notice: Option<&Map<String, Value>>) -> String {
    match notice {
        Some(fields) => guard_approval_question_message(Some(fields)),
        None => DEFAULT_PROMPT_CONTEXT.to_owned(),
    }
}

/// The `claude/permission_prompt` event as the daemon's `json.dumps` writes
/// it: the hook's own fields as it sent them, then the notice or `{}`, in
/// the daemon's key order. The notice reaches the daemon from the store
/// op's sorted JSON, so its keys are sorted there too.
pub(super) fn permission_prompt_event(
    payload: &Map<String, Value>,
    notice: Option<&Map<String, Value>>,
) -> Option<String> {
    let field = |key: &str| dumps_default(payload.get(key).unwrap_or(&Value::Null));
    let notice = dumps_default(&Value::Object(notice.cloned().unwrap_or_default()))?;
    Some(format!(
        "{{\"session_id\": {}, \"notification_type\": {}, \"tool_name\": {}, \"notice\": {notice}}}",
        field("session_id")?,
        field("notification_type")?,
        field("tool_name")?,
    ))
}

/// `_claude_permission_prompt_notification_response` once the caller has
/// loaded the notice, marked it seen and recorded the event.
pub(super) fn permission_prompt_notification_response(
    payload: &Map<String, Value>,
    notice: Option<&Map<String, Value>>,
) -> Value {
    json!({
        "systemMessage": permission_prompt_system_message(payload, notice),
        "hookSpecificOutput": {
            "hookEventName": NOTIFICATION,
            "additionalContext": permission_prompt_additional_context(notice),
        },
    })
}

#[cfg(test)]
#[path = "hook_direct_claude_permission_text_tests.rs"]
mod tests;
