//! Replay recorded JSONC normalizations through the Rust decoder.
//!
//! `normalize_jsonc` blanks comments and trailing commas without moving a
//! character, and Guard reads untrusted `bun.lock` files through it. Every
//! case below was produced by Python's `normalize_jsonc`, so an accepted
//! output is the one the CLI route produces for the same bytes.

use guard_command::jsonc::normalize_jsonc;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/guard-jsonc-normalization.v1.json");

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case is missing {field}"))
}

fn document() -> Value {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-jsonc-normalization-parity.v1",
        "fixture schema moved"
    );
    document
}

fn section<'a>(document: &'a Value, name: &str) -> &'a Vec<Value> {
    let cases = document[name].as_array().expect("section is a list");
    assert!(!cases.is_empty(), "the fixture records no {name}");
    cases
}

#[test]
fn recorded_normalizations_replay() {
    let document = document();
    for case in section(&document, "normalizations") {
        let name = text(case, "name");
        let source = text(case, "text");
        let normalized = normalize_jsonc(source)
            .unwrap_or_else(|error| panic!("case {name} was refused: {error}"));
        assert_eq!(
            normalized,
            text(case, "normalized"),
            "case {name} normalizes differently than Python"
        );
        // Every replacement is one character wide, so offsets never move.
        assert_eq!(
            normalized.chars().count(),
            source.chars().count(),
            "case {name} changed the character count"
        );
    }
}

#[test]
fn recorded_unterminated_comments_point_at_the_same_place() {
    let document = document();
    for case in section(&document, "unterminated") {
        let name = text(case, "name");
        let error = normalize_jsonc(text(case, "text"))
            .err()
            .unwrap_or_else(|| panic!("case {name} should be refused"));
        assert_eq!(
            error.to_string(),
            text(case, "message"),
            "case {name} reports a different position than Python"
        );
    }
}

#[test]
fn the_fixture_keeps_recording_a_comment_that_spans_lines() {
    // A block comment keeps its line breaks, so a later decode error reports
    // the line the reader sees. Losing this case would let that drift.
    let document = document();
    let mut spanning = 0usize;
    for case in section(&document, "normalizations") {
        let source = text(case, "text");
        let keeps_the_break = text(case, "normalized").contains('\n');
        if source.contains("/*") && source.contains('\n') && keeps_the_break {
            spanning += 1;
        }
    }
    assert!(spanning > 0, "no recorded block comment spans a line break");
}

#[test]
fn the_fixture_keeps_recording_an_unterminated_comment_past_line_one() {
    let document = document();
    assert!(
        section(&document, "unterminated")
            .iter()
            .any(|case| case["lineno"].as_u64().expect("recorded line") > 1),
        "every recorded unterminated comment starts on line 1"
    );
}
