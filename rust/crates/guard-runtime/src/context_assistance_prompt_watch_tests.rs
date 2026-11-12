use super::*;
use serde_json::json;

/// Watch answers Pi's prompt without a context slot. One is opened so CIGAR
/// can still add project context; a block or an answer that has one is left alone.
#[test]
fn a_watch_answer_gets_a_context_slot_only_when_it_allows_the_prompt() {
    let mut watch = json!({"decision": "allow", "policy_action": "allow", "reason_code": "watch"});
    assert!(open_slot(&mut watch));
    assert_eq!(
        watch["hookSpecificOutput"],
        json!({"hookEventName": "UserPromptSubmit"})
    );
    assert!(allowed(&watch));

    let mut slotted = json!({"continue": true, "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}});
    assert!(!open_slot(&mut slotted));

    let mut blocked = json!({"decision": "block"});
    assert!(!open_slot(&mut blocked));
    assert!(blocked.get("hookSpecificOutput").is_none());
}

/// The per-app choice is read from Guard's home config.
#[test]
fn cigar_off_is_read_per_app_from_the_home_config() {
    let home = tempfile::tempdir().unwrap();
    assert!(!crate::guard_config_load::cigar_off_for(home.path(), "codex"));
    std::fs::write(
        home.path().join("config.toml"),
        "[harness_cigar]\ncodex = \"off\"\nclaude-code = \"on\"\n",
    )
    .unwrap();
    assert!(crate::guard_config_load::cigar_off_for(home.path(), "codex"));
    assert!(!crate::guard_config_load::cigar_off_for(home.path(), "claude-code"));
}
