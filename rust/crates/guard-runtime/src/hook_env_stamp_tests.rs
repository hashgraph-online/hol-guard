//! Parity with the Python hook stamp and remaining-time hint, from vectors
//! recorded by `scripts/ci/record_claude_hook_bridge_vectors.py`.

use std::ffi::OsString;
use std::sync::OnceLock;

use serde_json::Value;

use super::*;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../testdata/claude_hook_bridge/vectors.json.gz");
const DECIDED: &str =
    r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}"#;
const RECURSION_ERROR: &str = "<error:RecursionError>";
const VALUE_ERROR: &str = "<error:ValueError>";

pub(crate) fn vectors() -> &'static Value {
    static PARSED: OnceLock<Value> = OnceLock::new();
    PARSED.get_or_init(|| gunzip_json(VECTORS))
}

/// Expands the recorder's tokens for its long texts.
pub(crate) fn expand(text: &str) -> String {
    let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    match text {
        "@deep" => format!("{{\"a\":{}}}", nested(30_000)),
        "@long_int" => format!("{{\"i\":{}}}", "9".repeat(5_000)),
        "@deep_output" => format!("{DECIDED},\"d\":{}}}", nested(30_000)),
        "@long_int_output" => format!("{DECIDED},\"i\":{}}}", "9".repeat(5_000)),
        other => other.to_owned(),
    }
}

/// The recorded result for `source`, with `@same` standing for the source.
pub(crate) fn expected(result: &str, source: &str) -> String {
    if result == "@same" {
        source.to_owned()
    } else {
        expand(result)
    }
}

pub(crate) fn text(value: &Value) -> &str {
    value.as_str().expect("vector field must be a string")
}

pub(crate) fn items(value: &Value) -> &[Value] {
    value.as_array().expect("vector field must be an array")
}

pub(crate) fn excerpt(text: &str) -> String {
    text.chars().take(80).collect()
}

#[cfg(unix)]
fn environment(pairs: &Value) -> DecodedEnvironment {
    use std::os::unix::ffi::OsStringExt;
    decode_environment(items(pairs).iter().map(|pair| {
        let bytes = |index: usize| {
            OsString::from_vec(hex::decode(text(&pair[index])).expect("hex environment"))
        };
        (bytes(0), bytes(1))
    }))
}

fn environment_of(pairs: &[(&str, &str)]) -> DecodedEnvironment {
    decode_environment(
        pairs
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
    )
}

fn stamped_text(stamp: Stamp) -> String {
    match stamp {
        Stamp::Text(text) => text,
        Stamp::Unrepresentable => panic!("stamp must be representable"),
    }
}

#[cfg(unix)]
#[test]
fn stamp_matches_python() {
    let vectors = vectors();
    let inputs: Vec<String> = items(&vectors["stamp_inputs"])
        .iter()
        .map(|input| expand(text(input)))
        .collect();
    for case in items(&vectors["stamp"]) {
        let environment = environment(&case["environment"]);
        let mut collected = String::new();
        dumps(
            &collect_hook_execution_environment(&environment),
            true,
            environment.mapped,
            &mut collected,
        );
        assert_eq!(collected, text(&case["collected"]));
        for (input, result) in inputs.iter().zip(items(&case["stamped"])) {
            let result = text(result);
            // A genuine private-use character next to a mapped surrogate is
            // refused instead of guessed; CPython could still tell them apart.
            let collides = environment.mapped && input.chars().any(in_surrogate_plane);
            let want = if result == RECURSION_ERROR || collides {
                Stamp::Unrepresentable
            } else {
                Stamp::Text(expected(result, input))
            };
            assert_eq!(
                stamp_hook_input_text(input, &environment),
                want,
                "input {}",
                excerpt(input)
            );
        }
    }
}

#[test]
fn remaining_hint_matches_python() {
    for case in items(&vectors()["hint"]) {
        let data = expand(text(&case["data"]));
        let raw_ms = case["raw_ms"].as_i64().expect("raw_ms");
        let hinted = with_remaining_hint(&data, u128::try_from(raw_ms.max(0)).unwrap_or(0));
        let result = text(&case["hinted"]);
        let want = match result {
            VALUE_ERROR => Err(JsonFailure::IntegerLimit),
            RECURSION_ERROR => Err(JsonFailure::Unrepresentable),
            _ => Ok(expected(result, &data)),
        };
        assert_eq!(hinted, want, "data {} at {raw_ms} ms", excerpt(&data));
    }
}

#[test]
fn first_duplicate_environment_name_wins() {
    let duplicated = environment_of(&[("PATH", "/first"), ("PATH", "/second"), ("HOME", "/h")]);
    let single = environment_of(&[("PATH", "/first"), ("HOME", "/h")]);
    assert_eq!(
        collect_hook_execution_environment(&duplicated),
        collect_hook_execution_environment(&single)
    );
}

#[test]
fn genuine_private_use_character_beside_lone_surrogate_is_refused() {
    let environment = environment_of(&[("PATH", "/bin")]);
    assert_eq!(
        stamp_hook_input_text("{\"a\":\"\u{f0000}\",\"b\":\"\\ud800\"}", &environment),
        Stamp::Unrepresentable
    );
    let stamped = stamped_text(stamp_hook_input_text("{\"a\":\"\u{f0000}\"}", &environment));
    assert!(
        stamped.starts_with("{\"a\":\"\\udb80\\udc00\","),
        "{stamped}"
    );
}

#[cfg(unix)]
#[test]
fn surrogate_escaped_environment_beside_private_use_value_is_refused() {
    use std::os::unix::ffi::OsStringExt;
    let environment = decode_environment([
        (OsString::from("A"), OsString::from_vec(b"\xff".to_vec())),
        (OsString::from("B"), OsString::from("\u{f0001}")),
    ]);
    assert!(environment.mapped && environment.collision);
    assert_eq!(
        stamp_hook_input_text("{}", &environment),
        Stamp::Unrepresentable
    );
}

#[test]
fn nesting_past_native_depth_is_refused() {
    let environment = environment_of(&[]);
    let deep = format!("{{\"a\":{}{}}}", "[".repeat(950), "]".repeat(950));
    assert_eq!(
        stamp_hook_input_text(&deep, &environment),
        Stamp::Unrepresentable
    );
    assert_eq!(
        with_remaining_hint(&deep, 10),
        Err(JsonFailure::Unrepresentable)
    );
}

#[test]
fn oversized_stamp_and_hint_forward_input_unchanged() {
    let environment = environment_of(&[("PATH", "/bin")]);
    let input = format!(
        "{{\"blob\":\"{}\"}}",
        "x".repeat(MAX_STAMPED_HOOK_INPUT_BYTES - 20)
    );
    assert_eq!(
        stamp_hook_input_text(&input, &environment),
        Stamp::Text(input.clone())
    );
    assert_eq!(with_remaining_hint(&input, 10), Ok(input.clone()));
    let fits = format!(
        "{{\"blob\":\"{}\"}}",
        "x".repeat(MAX_STAMPED_HOOK_INPUT_BYTES - 60)
    );
    assert_eq!(
        with_remaining_hint(&fits, 10),
        Ok(format!(
            "{},\"guard_remaining_ms\":10}}",
            &fits[..fits.len() - 1]
        ))
    );
}
