//! The resident decides on its own whether a call can be a verified patch.
//!
//! Only the question that needs the host's filesystem — are the patch's
//! target paths non-sensitive? — is left to the transport, so every other
//! condition closes the gate without asking anything.

use guard_contracts::HookCompositionInputsV1;
use serde_json::{json, Value};

use crate::hook_decision_native_facts::apply_patch_may_be_verified;

fn inputs(patch: Value, overrides: Value) -> HookCompositionInputsV1 {
    let mut value = json!({
        "harness": "codex",
        "canonical_harness": "codex",
        "event_fields": {"hook_event_name": "PreToolUse"},
        "tool_name_text": "apply_patch",
        "configured_action": "review",
        "has_configured_override": false,
        "has_narrow_override": false,
        "runtime_artifact_checked": true,
        "prompt_nonblank": false,
        "has_command_text": true,
        "facts": {},
        "native_request": {
            "tool_name": "apply_patch",
            "tool_input": patch,
            "cwd": "/work/project",
            "home_dir": "/work",
            "host": {
                "process_cwd": "/work/project",
                "home": "/work",
                "account_home": null,
                "groups": [],
                "environment": {"HOME": "/work"},
                "git_executable": null
            }
        }
    });
    for (key, replacement) in overrides.as_object().expect("overrides object") {
        value[key.as_str()] = replacement.clone();
    }
    serde_json::from_value(value).expect("composition inputs")
}

fn update() -> Value {
    json!({"patch": "*** Begin Patch\n*** Update File: README.md\n*** End Patch\n"})
}

#[test]
fn a_checked_codex_patch_reaches_the_target_path_question() {
    assert!(apply_patch_may_be_verified(&inputs(update(), json!({}))));
}

#[test]
fn the_patch_text_is_read_from_any_of_the_carrying_keys() {
    for key in ["patch", "input", "command"] {
        let body = json!({key: "*** Begin Patch\n*** Add File: notes.md\n*** End Patch\n"});
        assert!(
            apply_patch_may_be_verified(&inputs(body, json!({}))),
            "{key} carries the patch"
        );
    }
}

#[test]
fn a_patch_that_removes_or_relocates_a_file_is_never_verified() {
    for marker in ["*** Delete File: README.md", "*** Move to: docs/README.md"] {
        let body = json!({"patch": format!("*** Begin Patch\n{marker}\n*** End Patch\n")});
        assert!(
            !apply_patch_may_be_verified(&inputs(body, json!({}))),
            "{marker} closes the gate"
        );
    }
}

#[test]
fn nothing_but_a_checked_codex_apply_patch_opens_the_gate() {
    for overrides in [
        json!({"canonical_harness": "cursor"}),
        json!({"runtime_artifact_checked": false}),
        json!({"native_request": null}),
    ] {
        assert!(
            !apply_patch_may_be_verified(&inputs(update(), overrides.clone())),
            "{overrides} closes the gate"
        );
    }
}

#[test]
fn the_tool_name_comes_off_the_request_not_the_payload_text() {
    let mut request = inputs(update(), json!({}));
    request.tool_name_text = "Bash".to_owned();
    assert!(apply_patch_may_be_verified(&request));

    if let Some(native) = request.native_request.as_mut() {
        native.tool_name = json!("  APPLY_PATCH  ");
    }
    assert!(apply_patch_may_be_verified(&request));

    if let Some(native) = request.native_request.as_mut() {
        native.tool_name = json!("bash");
    }
    assert!(!apply_patch_may_be_verified(&request));
}

#[test]
fn a_patch_with_no_text_to_read_is_not_verified() {
    for body in [
        json!({}),
        json!({"patch": "   "}),
        json!({"patch": 7}),
        json!(""),
    ] {
        assert!(
            !apply_patch_may_be_verified(&inputs(body.clone(), json!({}))),
            "{body} carries no patch"
        );
    }
}
