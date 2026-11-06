//! Parity vectors recorded from the retired Python approval-question match.

use std::io::Read;

use flate2::read::GzDecoder;
use guard_contracts::{ClaudeGuardQuestionVerdictV1, ContextDigestKindV1};
use serde_json::{json, Value};

use super::{verdict, Question};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/claude_guard_question_vectors.json.gz");

fn vectors() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    document["cases"].as_array().unwrap().clone()
}

#[test]
fn verdicts_match_the_retired_python() {
    let cases = vectors();
    assert_eq!(cases.len(), 90);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut wire = case["request"].clone();
        wire["kind"] = json!("claude_guard_question");
        let ContextDigestKindV1::ClaudeGuardQuestion {
            event,
            tool_name,
            tool_input,
            tool_response,
            response_answers,
            pending,
        } = serde_json::from_value(wire).unwrap_or_else(|error| panic!("{name}: {error}"))
        else {
            panic!("{name}: wrong kind");
        };
        let actual = verdict(&Question {
            event: event.as_deref(),
            tool_name: &tool_name,
            tool_input: &tool_input,
            tool_response: &tool_response,
            response_answers: response_answers.as_deref(),
            pending: &pending,
        });
        let expected: ClaudeGuardQuestionVerdictV1 =
            serde_json::from_value(case["expected"].clone()).unwrap();
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn final_sigma_follows_python_lower() {
    let cases = [
        ("ΑΣ", "ας"),
        ("A Σ", "a σ"),
        ("ΑΣ ", "ας"),
        ("ΟΔΟΣ", "οδος"),
        ("Α\u{0301}Σ", "α\u{0301}ς"),
        ("Α Σ", "α σ"),
        ("Σ\u{0301}", "σ\u{0301}"),
        ("Α.\u{0301}Σ", "α.\u{0301}ς"),
        ("12Σ", "12σ"),
        ("Σ1", "σ1"),
        ("İ", "i\u{0307}"),
        ("STRASSE", "strasse"),
        ("straße", "straße"),
        ("Σ", "σ"),
        ("ΣΑ", "σα"),
        ("ΑΣΑ", "ασα"),
        ("A.Σ", "a.ς"),
    ];
    for (input, expected) in cases {
        assert_eq!(super::normalize(input), expected, "{input}");
    }
}

#[test]
fn a_pending_that_is_not_an_object_is_not_a_question() {
    let answer = json!("Allow once");
    let actual = verdict(&Question {
        event: Some("PostToolUse"),
        tool_name: &json!("AskUserQuestion"),
        tool_input: &Value::Null,
        tool_response: &answer,
        response_answers: None,
        pending: &Value::Null,
    });
    assert!(!actual.is_question);
    assert_eq!(actual.action, None);
}
