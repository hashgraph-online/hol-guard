//! A structured field that is present and empty names nothing. These cases pin
//! that reading, and pin the payloads that must still be refused beside it.

use guard_command::pretool::evaluate_pre_tool_envelope;
use guard_command::MAX_COMMAND_BYTES;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

fn generic(payload: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope("claude-code", "PreToolUse", &payload)
}

/// A harness-native search tool spells "start where the project does" as an
/// empty path argument. The field is present and its type is right, so the
/// payload parses; there is simply no target in it, and a call that names no
/// target must not be read as a malformed payload and blocked.
#[test]
fn a_blank_structured_field_names_nothing_rather_than_breaking_the_payload() {
    for payload in [
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": ""}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": "   "}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": "", "pattern": "**/*.md"}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "glob", "tool_input": {"path": ["", "src"]}}),
        json!({"hook_event_name": "PreToolUse", "tool_name": "grep", "tool_input": {"path": "", "pattern": "retryLimit"}}),
    ] {
        let result = evaluate_pre_tool_envelope("omp", "PreToolUse", &payload);
        assert_ne!(
            result.reason_code, "native_pre_tool_malformed_payload",
            "{payload}"
        );
        assert_ne!(result.minimum_action, "block", "{payload}");
    }
}

/// The blank reading applies to the fields that name a target, and nowhere
/// else. A payload that genuinely cannot be read, one that says two different
/// things, and one that exceeds the command bound each keep the answer they
/// had.
#[test]
fn unreadable_conflicting_and_oversized_payloads_still_block() {
    for unreadable in [
        json!({"tool_name": "glob", "tool_input": {"path": {"a": 1}}}),
        json!({"tool_name": "glob", "tool_input": {"path": null}}),
        json!({"tool_name": "glob", "tool_input": {"path": ["src", null]}}),
    ] {
        let result = generic(unreadable.clone());
        assert_eq!(result.minimum_action, "block", "{unreadable}");
        assert_eq!(
            result.reason_code, "native_pre_tool_malformed_payload",
            "{unreadable}"
        );
    }

    for blank_command in [
        json!({"tool_name": "Bash", "tool_input": {"command": ""}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "   "}}),
    ] {
        let result = generic(blank_command.clone());
        assert_eq!(result.minimum_action, "block", "{blank_command}");
        assert_eq!(
            result.reason_code, "native_pre_tool_malformed_payload",
            "{blank_command}"
        );
    }

    let oversized = generic(json!({
        "tool_name": "glob",
        "tool_input": {"path": "a".repeat(MAX_COMMAND_BYTES + 1)}
    }));
    assert_eq!(oversized.minimum_action, "block");
    assert_eq!(oversized.reason_code, "native_pre_tool_bounds_exceeded");

    let conflict = generic(json!({"command": "pwd", "cmd": "whoami"}));
    assert_eq!(conflict.minimum_action, "block");
    assert_eq!(conflict.reason_code, "native_pre_tool_ambiguous_payload");

    // A blank path is absent, not a read of nothing: the read-nothing proof
    // still needs an empty list or a null, so this call keeps its review.
    let blank_path = generic(json!({"tool_name": "Read", "tool_input": {"file_path": ""}}));
    assert_ne!(blank_path.reason_code, "native_empty_file_read_request");

    // Only a blank string reads as absent. A null target is not a read of
    // nothing either, so it can never earn that allow.
    let null_path = generic(json!({"tool_name": "Read", "tool_input": {"file_path": null}}));
    assert_ne!(null_path.minimum_action, "allow");
    assert_ne!(null_path.reason_code, "native_empty_file_read_request");
}

/// A file body skips the command-size bound only because the path beside it is
/// the value the decision reads. A path that names nothing cannot buy that
/// exemption, so an oversized body beside a blank path is still out of bounds.
#[test]
fn a_blank_path_does_not_exempt_the_body_beside_it_from_its_bound() {
    for path in [json!(""), json!("   "), json!([""]), json!([])] {
        let result = generic(json!({
            "tool_name": "Edit",
            "tool_input": {"path": path, "content": "a".repeat(MAX_COMMAND_BYTES + 1)}
        }));
        assert_eq!(result.minimum_action, "block", "{path}");
        assert_eq!(
            result.reason_code, "native_pre_tool_bounds_exceeded",
            "{path}"
        );
    }
    // A path that does name a file keeps the exemption: the body may be large.
    let named = generic(json!({
        "tool_name": "Edit",
        "tool_input": {"path": "src/report.ts", "content": "a".repeat(MAX_COMMAND_BYTES + 1)}
    }));
    assert_ne!(named.reason_code, "native_pre_tool_bounds_exceeded");
}
