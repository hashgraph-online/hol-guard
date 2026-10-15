//! Lone surrogates through the native Cursor bridge, against vectors
//! recorded from the generated Cursor client: the payload
//! `_prepare_cursor_hook_payload` builds, written as `json.dumps` writes it,
//! and the answer `_emit_cursor_response` prints.

use std::time::{Duration, Instant};

use serde_json::Value;

use super::*;
use crate::hook_env_stamp::HOOK_EXECUTION_ENVIRONMENT_KEY;

const SURROGATES: &str = include_str!("../testdata/cursor_hook_bridge/surrogates.json");

fn vectors(name: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(SURROGATES).unwrap();
    assert_eq!(all["schema"], "hol-guard-cursor-native-surrogates.v1");
    all[name].as_array().unwrap().clone()
}

fn text(vector: &Value, key: &str) -> String {
    vector[key].as_str().unwrap().to_owned()
}

fn surrogate_client() -> Client {
    Client {
        guard_home: "/g".to_owned(),
        home: Some("/h".to_owned()),
        recovery_command: Vec::new(),
        event: "preToolUse".to_owned(),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

#[test]
fn hooks_with_lone_surrogates_are_sent_as_the_client_sends_them() {
    let client = surrogate_client();
    let requests = vectors("requests");
    assert!(requests.len() >= 7);
    for vector in requests {
        let input = text(&vector, "input");
        let request = prepared_request(&client, input.as_bytes())
            .unwrap_or_else(|| panic!("not sent: {input}"));
        assert_eq!(request.event, text(&vector, "event"), "{input}");
        let sent = text(&vector, "sent");
        let members = format!(
            "{},\"{HOOK_EXECUTION_ENVIRONMENT_KEY}\":",
            &sent[..sent.len() - 1]
        );
        assert!(
            request.data.starts_with(&members),
            "{input}\n{}",
            request.data
        );
        assert!(request.data.contains("\\ud"), "{input}");
    }
}

#[test]
fn answers_with_lone_surrogates_print_as_the_client_prints_them() {
    let answers = vectors("answers");
    assert!(answers.len() >= 20);
    for vector in answers {
        let response = text(&vector, "response");
        let code = i32::try_from(vector["exit_code"].as_i64().unwrap()).unwrap();
        let expected = Some((text(&vector, "stdout"), code));
        let event = text(&vector, "event");
        assert_eq!(
            answer(Kind::PreToolUse, &event, &response, Path::new("/g")),
            expected,
            "{event} {response}"
        );
    }
}

#[test]
fn a_lone_surrogate_beside_its_mapped_range_runs_the_client() {
    let client = surrogate_client();
    let raw = "{\"hook_event_name\":\"beforeShellExecution\",\"command\":\"\\ud800\u{f0000}\"}";
    assert_eq!(prepared_request(&client, raw.as_bytes()), None);
    assert_eq!(python_document("{\"a\":\"\\ud800\u{f0000}\"}"), None);
    assert_eq!(python_document("{\"a\":\"\\ud800\",\"b\":NaN}"), None);
    let block = "{\"policy_action\":\"block\",\"reason\":\"\\ud800\u{f0000}\"}";
    assert_eq!(
        answer(Kind::PreToolUse, "preToolUse", block, Path::new("/g")),
        None
    );
    // A genuine character of that range, with no lone surrogate, is kept.
    let genuine = "{\"policy_action\":\"block\",\"reason\":\"\u{f0000}\"}";
    let (stdout, _) = answer(Kind::PreToolUse, "preToolUse", genuine, Path::new("/g")).unwrap();
    assert!(stdout.contains("\\udb80\\udc00"), "{stdout}");
}

#[test]
fn a_path_holding_a_lone_surrogate_is_never_the_workspace() {
    let root = std::env::temp_dir().join(format!(
        "cursor-hook-bridge-surrogate-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("\u{f0000}")).unwrap();
    std::fs::create_dir_all(root.join("cwd")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let base = root.to_str().unwrap();
    let raw = format!(
        "{{\"workspace_roots\":[{}],\"cwd\":{}}}",
        serde_json::to_string(&format!("{base}/\\ud800"))
            .unwrap()
            .replace("\\\\ud800", "\\ud800"),
        serde_json::to_string(&format!("{base}/cwd")).unwrap(),
    );
    let Some((OValue::Map(payload), true)) = python_document(&raw) else {
        panic!("{raw}");
    };
    assert_eq!(
        workspace(&payload, None, true),
        Ok(Some(format!("{base}/cwd")))
    );
    // The same directory named by its genuine character is one.
    assert_eq!(
        workspace(&payload, None, false),
        Ok(Some(format!("{base}/\u{f0000}")))
    );
    std::fs::remove_dir_all(root).unwrap();
}
