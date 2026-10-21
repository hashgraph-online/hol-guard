//! Parity with the Python Claude bridge's event read, deny shapes and
//! response validation, from vectors recorded by
//! `scripts/ci/record_claude_hook_bridge_vectors.py`.

use super::*;
use crate::hook_env_stamp::tests::{excerpt, expand, expected, items, text, vectors};

fn strings(value: &serde_json::Value) -> Vec<String> {
    items(value)
        .iter()
        .map(|item| text(item).to_owned())
        .collect()
}

#[test]
fn renders_match_python() {
    let vectors = vectors();
    let reasons = strings(&vectors["reasons"]);
    let bodies = strings(&vectors["suppress_bodies"]);
    for case in items(&vectors["render"]) {
        let data = expand(text(&case["data"]));
        let event = event_name(&data);
        if case["string_event"].as_bool() == Some(true) {
            assert_eq!(
                event.json(),
                text(&case["event"]),
                "data {}",
                excerpt(&data)
            );
        } else {
            assert_eq!(event.name, NON_STRING_EVENT, "data {}", excerpt(&data));
        }
        assert_eq!(
            limit_denied("hook input", &event),
            text(&case["limit_denied"]),
            "data {}",
            excerpt(&data)
        );
        for (reason, want) in reasons.iter().zip(items(&case["degraded"])) {
            assert_eq!(
                degraded(reason, &data),
                text(want),
                "data {}",
                excerpt(&data)
            );
        }
        for (reason, want) in reasons.iter().zip(items(&case["control_plane"])) {
            assert_eq!(
                control_plane_failure(reason, &data),
                text(want),
                "data {}",
                excerpt(&data)
            );
        }
        for (body, want) in bodies.iter().zip(items(&case["suppress"])) {
            assert_eq!(
                should_suppress_output(&data, body),
                want.as_bool().expect("suppress flag"),
                "data {} body {body:?}",
                excerpt(&data)
            );
        }
    }
}

#[test]
fn response_validation_matches_python() {
    let vectors = vectors();
    let reason = text(&vectors["reasons"][1]);
    for case in items(&vectors["validate"]) {
        let output = expand(text(&case["output"]));
        let data = expand(text(&case["data"]));
        let result = text(&case["result"]);
        let want = match result {
            "<error:ValueError>" => Err(JsonFailure::IntegerLimit),
            "<error:RecursionError>" => Err(JsonFailure::Unrepresentable),
            _ => Ok(expected(result, &output)),
        };
        assert_eq!(
            valid_hook_json_or_degraded(&output, reason, &data),
            want,
            "output {} data {}",
            excerpt(&output),
            excerpt(&data)
        );
    }
}

#[test]
fn event_read_past_integer_limit_falls_back_to_prefix_and_denies() {
    // CPython raises out of `_event_name` here and Claude Code would see a
    // crashed hook; the native bridge reads the prefix and still denies.
    let data = format!(
        "{{\"hook_event_name\":\"PermissionRequest\",\"n\":{}}}",
        "9".repeat(5_000)
    );
    let event = event_name(&data);
    assert_eq!(event.name, "PermissionRequest");
    let denied = degraded("daemon unavailable", &data);
    assert!(
        denied.contains("\"decision\":{\"behavior\":\"deny\""),
        "{denied}"
    );
}

#[test]
fn event_read_past_native_depth_falls_back_to_prefix() {
    let data = format!(
        "{{\"hook_event_name\":\"Stop\",\"d\":{}{}}}",
        "[".repeat(950),
        "]".repeat(950)
    );
    assert_eq!(event_name(&data).name, "Stop");
}

#[test]
fn python_strip_also_trims_information_separators() {
    assert_eq!(py_strip("\u{1c}\u{1f} {} \u{85}\u{3000}"), "{}");
    assert_eq!(py_strip("\u{200b}x"), "\u{200b}x");
}
