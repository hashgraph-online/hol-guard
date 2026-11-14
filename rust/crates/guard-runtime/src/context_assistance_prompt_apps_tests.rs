//! Which apps' prompt hooks get CIGAR's project context, and the field each
//! one reads it from.

use serde_json::json;

use super::{kimi_message, prompt_text, takes_context};

#[test]
fn every_app_whose_prompt_hook_reaches_the_model_takes_context() {
    let plain = json!({"prompt": "fix the cart"});
    for harness in [
        "claude-code",
        "codex",
        "devin",
        "muse",
        "zcode",
        "kimi",
        "cline",
    ] {
        assert!(takes_context(harness, &plain), "{harness}");
    }
    // Copilot CLI and Grok drop an allowing prompt hook's output; Cursor's
    // prompt hook can only allow or block; Hermes has no prompt hook.
    let flagged = json!({"prompt": "fix the cart", "guard_prompt_context": true});
    for harness in [
        "copilot",
        "grok",
        "cursor",
        "hermes",
        "gemini",
        "antigravity",
    ] {
        assert!(!takes_context(harness, &flagged), "{harness}");
    }
}

#[test]
fn kimi_reads_the_context_from_message() {
    let mut response = json!({"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": "HOL Guard CIGAR found code"
    }});
    kimi_message(&mut response);
    assert_eq!(
        response["hookSpecificOutput"]["message"],
        "HOL Guard CIGAR found code"
    );

    let mut empty = json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}});
    kimi_message(&mut empty);
    assert!(empty["hookSpecificOutput"].get("message").is_none());
}

#[test]
fn cline_prompts_are_read_from_their_nested_field() {
    let cline = json!({"hookName": "UserPromptSubmit",
        "userPromptSubmit": {"prompt": "fix the cart total"}});
    assert_eq!(prompt_text(&cline), Some("fix the cart total"));
    assert_eq!(prompt_text(&json!({"prompt": "fix it"})), Some("fix it"));
    assert_eq!(prompt_text(&json!({"hookName": "UserPromptSubmit"})), None);
}
