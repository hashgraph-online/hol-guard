//! The `hol-guard hook` command reads a daemon answer as the Python
//! `emit_hook_review` did. The vectors hold what `_daemon_response_to_native`
//! printed for a bridge-rendered harness and the policy action its exit
//! status followed for every other one.

use serde_json::Value;

use super::cli_hook_emit_document;

const VECTORS: &str = include_str!("../testdata/hook_cli_emit/vectors.json");

fn field<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key].as_str().expect("vector field")
}

#[test]
fn every_vector_reads_as_python_read_it() {
    let cases: Value = serde_json::from_str(VECTORS).expect("vectors");
    let cases = cases.as_array().expect("cases");
    assert!(cases.len() >= 20, "vector set shrank");
    for case in cases {
        let document = cli_hook_emit_document(
            field(case, "harness"),
            field(case, "event_name"),
            field(case, "response"),
        )
        .unwrap_or_else(|| panic!("no document for {case}"));
        if let Some(action) = case.get("policy_action") {
            assert_eq!(document.get("policy_action"), Some(action), "{case}");
            assert_eq!(document.len(), 1, "{case}");
            continue;
        }
        for key in ["stdout", "stderr", "exit_code"] {
            assert_eq!(document.get(key), case.get(key), "{key} for {case}");
        }
    }
}

#[test]
fn a_lone_surrogate_reason_prints_as_its_escape() {
    let document = cli_hook_emit_document(
        "kimi",
        "PreToolUse",
        r#"{"policy_action":"block","reason":"x\ud800"}"#,
    )
    .expect("document");
    assert_eq!(document["exit_code"], 2);
    assert_eq!(document["stderr"], "x\\ud800");
    assert!(document["stdout"]
        .as_str()
        .expect("stdout")
        .contains(r#""permissionDecisionReason":"x\ud800""#));
}

#[test]
fn an_unreadable_answer_has_no_document() {
    for (harness, text) in [
        ("kimi", "[]"),
        ("codex", "not json"),
        // Python would print a list reason through `repr`; the caller fails
        // closed instead of guessing that text.
        ("kimi", r#"{"policy_action":"block","reason":["a"]}"#),
    ] {
        assert!(
            cli_hook_emit_document(harness, "PreToolUse", text).is_none(),
            "{harness} {text}"
        );
    }
}

#[test]
fn grok_reads_an_empty_answer_by_event() {
    for (event, exit_code) in [
        ("SessionStart", 0),
        ("UserPromptSubmit", 0),
        ("PreToolUse", 2),
    ] {
        let document = cli_hook_emit_document("grok", event, "{}").expect("document");
        assert_eq!(document["exit_code"], exit_code, "{event}");
    }
}
