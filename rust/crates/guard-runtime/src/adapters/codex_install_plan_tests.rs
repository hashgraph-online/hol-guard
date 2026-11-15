//! Replays `codex_install_plan_vectors.json`, recorded from the original Python
//! helpers, through the native kind. Shell cleanups are rebuilt from the
//! request's bytes and the answered ranges, the way the Python shim keeps them.

use serde_json::{json, Value};

use crate::codex_install_plan::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/codex/codex_install_plan_vectors.json");
const SCHEMA: &str = "guard-codex-install-plan-vectors.v1";

fn vectors() -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(vectors["schema"], SCHEMA);
    vectors
}

fn bytes(text: &str) -> Vec<u8> {
    text.chars()
        .map(|character| u8::try_from(u32::from(character)).expect("latin-1"))
        .collect()
}

fn kept(content: &[u8], ranges: &Value) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut position = 0;
    for range in ranges.as_array().expect("ranges") {
        let start = usize::try_from(range[0].as_u64().expect("start")).expect("usize");
        let end = usize::try_from(range[1].as_u64().expect("end")).expect("usize");
        assert!(position <= start && start < end && end <= content.len());
        kept.extend_from_slice(&content[position..start]);
        position = end;
    }
    kept.extend_from_slice(&content[position..]);
    kept
}

#[test]
fn shell_blocks_replay_the_python_cleanup() {
    let vectors = vectors();
    let cases = vectors["shell_blocks"].as_array().expect("cases");
    assert!(cases.len() >= 20);
    for case in cases {
        let content = case["content"].as_str().expect("content");
        let answer = dispatch(&json!({ "op": "shell_blocks", "content": content }))
            .expect("shell_blocks answers");
        assert_eq!(
            kept(&bytes(content), &answer["ranges"]),
            bytes(case["cleaned"].as_str().expect("cleaned")),
            "{content:?}"
        );
    }
}

#[test]
fn guard_proxies_replay_the_python_recognizer() {
    let vectors = vectors();
    let cases = vectors["guard_proxies"].as_array().expect("cases");
    assert!(cases.len() >= 15);
    let servers: serde_json::Map<String, Value> = cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            (
                format!("server-{index}"),
                json!({ "command": case["command"], "args": case["args"] }),
            )
        })
        .collect();
    let answer = dispatch(&json!({ "op": "guard_proxies", "servers": servers }))
        .expect("guard_proxies answers");
    let names: Vec<&str> = answer["names"]
        .as_array()
        .expect("names")
        .iter()
        .map(|name| name.as_str().expect("name"))
        .collect();
    for (index, case) in cases.iter().enumerate() {
        let name = format!("server-{index}");
        assert_eq!(
            names.contains(&name.as_str()),
            case["guard"].as_bool().expect("guard"),
            "{case}"
        );
    }
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({ "op": "shell_blocks" }),
        json!({ "op": "shell_blocks", "content": 1 }),
        json!({ "op": "shell_blocks", "content": "\u{100}" }),
        json!({ "op": "shell_blocks", "content": "", "extra": 1 }),
        json!({ "op": "guard_proxies", "servers": [] }),
        json!({ "op": "guard_proxies", "servers": { "a": { "command": 1, "args": [] } } }),
        json!({ "op": "guard_proxies", "servers": { "a": { "command": null, "args": [1] } } }),
        json!({ "op": "guard_proxies", "servers": { "a": { "command": null } } }),
        json!({ "op": "unknown" }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
