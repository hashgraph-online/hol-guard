use serde_json::{json, Value};

use super::*;

const VECTORS: &str = include_str!("../../../../tests/fixtures/redacted-command-tokens.v1.json");

fn joined(parts: &Value) -> String {
    parts
        .as_array()
        .expect("fragments")
        .iter()
        .map(|part| part.as_str().expect("fragment"))
        .collect()
}

#[test]
fn every_recorded_command_redacts_to_its_recorded_tokens() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 19);
    for case in cases {
        let command: Vec<String> = case["command"]
            .as_array()
            .expect("command")
            .iter()
            .map(joined)
            .collect();
        let redacted: Vec<String> =
            serde_json::from_value(case["redacted"].clone()).expect("redacted");
        assert_eq!(
            dispatch(&json!({ "command": command })).expect("answer"),
            json!({ "text": crate::mcp_proxy_shlex::join(&redacted) }),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_redacted_tokens_are_joined_as_shlex_joins_them() {
    let secret = ["s3", "cr3t"].concat();
    let source = format!("https://user:{secret}@registry.example.test/pkg.tgz");
    let assignment = format!("NPM_TOKEN={secret}");
    let answer = dispatch(&json!({
        "command": ["npm", "install", source, assignment, "two words", ""],
    }))
    .expect("answer");
    let text = answer["text"].as_str().expect("text");
    assert!(!text.contains(&secret), "{text}");
    assert_eq!(
        text,
        "npm install https://registry.example.test/pkg.tgz 'NPM_TOKEN=*****' 'two words' ''"
    );
}

#[test]
fn malformed_requests_are_invalid() {
    let too_many = vec![json!("npm"); MAX_TOKENS + 1];
    for args in [
        json!([]),
        json!({}),
        json!({ "command": "npm install" }),
        json!({ "command": ["npm", 1] }),
        json!({ "command": too_many }),
        json!({ "command": ["npm"], "extra": true }),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
    assert_eq!(
        dispatch(&json!({ "command": [] })).expect("answer"),
        json!({ "text": "" })
    );
}
