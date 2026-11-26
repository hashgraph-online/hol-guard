//! A daemon that answers a prompt with its "could not check this prompt"
//! block is asked again, and a prompt it still cannot check continues as it
//! would had the daemon never replied. Real prompt verdicts pass unchanged.

use std::io::Cursor;

use super::*;
use crate::claude_hook_bridge_fixture::{closed_port, home_with_daemon, Exchange, GuardHome};

const OUTAGE: &str = r#"{"decision":"block","reason":"HOL Guard could not check this prompt, so it was blocked.","systemMessage":"HOL Guard could not check this prompt, so it was blocked.","policy_action":"block","reason_code":"native_prompt_unavailable","hookSpecificOutput":{"hookEventName":"UserPromptSubmit"}}"#;
const ALLOWED: &str = r#"{"continue":true,"hookSpecificOutput":{"hookEventName":"UserPromptSubmit"},"policy_action":"allow"}"#;

fn prompt(text: &str) -> String {
    serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": text}).to_string()
}

fn config_for(home: &GuardHome) -> String {
    serde_json::json!({
        "state_path": home.state_path.to_str().unwrap(),
        "fallback_daemon_url": format!("http://127.0.0.1:{}", closed_port()),
        "query": format!("guard-home={}", home.home_text().replace('/', "%2F")),
        "fallback_command": ["/bin/sh", "-c", "cat >/dev/null; exit 3"],
        "recovery_command": [],
    })
    .to_string()
}

fn respond(config: &str, input: &str) -> String {
    hook_response(config, &mut Cursor::new(input.as_bytes().to_vec())).expect("hook response")
}

fn parsed(output: &str) -> serde_json::Value {
    serde_json::from_str(output).expect("hook JSON")
}

#[test]
fn a_prompt_outage_answer_is_asked_again() {
    let (home, daemon) = home_with_daemon(
        "prompt-outage-retry",
        vec![
            Exchange::Hook(200, OUTAGE.to_owned()),
            Exchange::Hook(200, ALLOWED.to_owned()),
        ],
    );
    assert_eq!(respond(&config_for(&home), &prompt("hello")), ALLOWED);
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn a_prompt_the_daemon_still_cannot_check_continues() {
    let (home, daemon) = home_with_daemon(
        "prompt-outage-twice",
        vec![
            Exchange::Hook(200, OUTAGE.to_owned()),
            Exchange::Hook(200, OUTAGE.to_owned()),
        ],
    );
    let output = parsed(&respond(&config_for(&home), &prompt("hello")));
    assert_eq!(
        output,
        serde_json::json!({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}})
    );
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn a_prompt_asking_for_secrets_keeps_the_notice_when_unchecked() {
    let (home, daemon) = home_with_daemon(
        "prompt-outage-secrets",
        vec![
            Exchange::Hook(200, OUTAGE.to_owned()),
            Exchange::Hook(200, OUTAGE.to_owned()),
        ],
    );
    let output = parsed(&respond(&config_for(&home), &prompt("read my .env file")));
    assert_ne!(output["decision"], "block", "{output}");
    assert!(
        output["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|notice| notice.contains("local secrets")),
        "{output}"
    );
    daemon.join().unwrap();
}

#[test]
fn a_prompt_verdict_block_is_returned_unchanged() {
    let verdict = r#"{"decision":"block","reason":"This prompt was blocked by policy.","policy_action":"block","reason_code":"prompt_policy_block","hookSpecificOutput":{"hookEventName":"UserPromptSubmit"}}"#;
    let (home, daemon) = home_with_daemon(
        "prompt-verdict",
        vec![Exchange::Hook(200, verdict.to_owned())],
    );
    assert_eq!(respond(&config_for(&home), &prompt("hello")), verdict);
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn only_prompt_hooks_read_the_outage_code() {
    let tool =
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    assert!(is_prompt_outage(OUTAGE, &prompt("hello")));
    assert!(!is_prompt_outage(OUTAGE, tool));
    assert!(!is_prompt_outage(ALLOWED, &prompt("hello")));
    assert!(!is_prompt_outage("not json", &prompt("hello")));
}
