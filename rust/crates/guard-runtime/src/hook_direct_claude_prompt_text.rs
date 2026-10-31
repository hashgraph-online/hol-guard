//! Guard's Claude Code notice on a reviewed `UserPromptSubmit`.
//!
//! Outside Watch the edge overlays Claude's prompt response with a branded
//! system message and, for a prompt that needs reapproval, a briefing for the
//! model. The action and reason come from the native result; this only
//! renders Guard's copy for them, so the direct lane and the daemon return
//! the same notice.

use serde_json::Value;

use super::claude_permission_text::ensure_terminal_punctuation;
use super::HookDirectDefer;

/// Native classes the daemon reads as a request for local secrets.
const SECRET_READ_CLASSES: [&str; 3] = ["local_env_read", "sensitive_material", "secret_read"];
const HARD_BLOCK_CLASS: &str = "guard_bypass_intent";

const SECRET_SYSTEM_MESSAGE: &str = "HOL Guard intercepted this prompt because it asks Claude to access local secrets. If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt.";
const SENSITIVE_SYSTEM_MESSAGE: &str = "HOL Guard intercepted this prompt because it leads to a sensitive action. If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt.";
const SECRET_BRIEFING: &str = "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded approval question to protect you.";
const SENSITIVE_BRIEFING: &str =
    "HOL Guard will intercept Claude's next sensitive action and open a branded approval question.";

/// Adds the daemon's notice to `response` for the native `result`.
///
/// A reason that is not text, or a response that is not an object, leaves
/// `response` unchanged and reports why.
pub(crate) fn brand(response: &mut Value, result: &Value) -> Result<(), HookDirectDefer> {
    let action = match result.get("minimum_action") {
        Some(Value::String(action)) => action.as_str(),
        _ => return Ok(()),
    };
    let reason = match result.get("reason") {
        None | Some(Value::Null) => "",
        Some(Value::String(reason)) => reason.as_str(),
        Some(_) => return Err(HookDirectDefer::PromptNotice),
    };
    let classes: Vec<&str> = match result.get("prompt_risk_classes") {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let hard_block = classes.contains(&HARD_BLOCK_CLASS);
    let secret = classes
        .iter()
        .any(|class| SECRET_READ_CLASSES.contains(class));
    let Some(response) = response.as_object_mut() else {
        return Err(HookDirectDefer::PromptNotice);
    };
    let reapproval = action == "require-reapproval" && !hard_block;
    let system_message = if reapproval {
        Some(if secret {
            SECRET_SYSTEM_MESSAGE.to_owned()
        } else {
            SENSITIVE_SYSTEM_MESSAGE.to_owned()
        })
    } else if matches!(action, "block" | "sandbox-required") {
        Some(ensure_terminal_punctuation(reason))
    } else {
        None
    };
    if let Some(message) = system_message.filter(|message| !message.is_empty()) {
        response.insert("systemMessage".to_owned(), Value::String(message));
    }
    if reapproval {
        let briefing = if secret {
            SECRET_BRIEFING
        } else {
            SENSITIVE_BRIEFING
        };
        let context = format!(
            "{} Do not ask for approval at the prompt stage. Attempt the intended sensitive tool once so HOL Guard can evaluate the exact tool, path, and arguments, then route that concrete action into a HOL Guard approval question with Allow once, Allow during this session, and Keep blocked. First tell the user exactly: '{briefing}' Attempt that sensitive tool at most once. If HOL Guard or Claude denies it, do not retry the same sensitive action automatically. Instead, tell the user approval is required in Claude to continue.",
            ensure_terminal_punctuation(reason)
        );
        if let Some(Value::Object(output)) = response.get_mut("hookSpecificOutput") {
            output.insert("additionalContext".to_owned(), Value::String(context));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "hook_direct_claude_prompt_text_tests.rs"]
mod tests;
