use super::HOME;
use crate::hook_direct::{
    direct_event, expanduser, normalized_workspace, normpath, workspace_candidate, HookDirectDefer,
};
use serde_json::{json, Map, Value};

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn event_name_follows_the_daemon_rule() {
    assert_eq!(direct_event(&object(json!({}))), Ok(Some("PreToolUse")));
    for name in [
        "PreToolUse",
        " pre_tool_use ",
        "pre-tool-call",
        "beforeShellExecution",
    ] {
        assert_eq!(
            direct_event(&object(json!({ "hook_event_name": name }))),
            Ok(Some("PreToolUse")),
            "{name}"
        );
    }
    for name in ["PostToolUse", "post_tool_call", " afterShellExecution "] {
        assert_eq!(
            direct_event(&object(json!({ "hook_event_name": name }))),
            Ok(Some("PostToolUse")),
            "{name}"
        );
    }
    for name in ["UserPromptSubmit", "prompt", "user-prompt-submitted"] {
        assert_eq!(
            direct_event(&object(json!({ "hook_event_name": name }))),
            Ok(Some("UserPromptSubmit")),
            "{name}"
        );
    }
    assert_eq!(
        direct_event(&object(json!({ "hook_event_name": "PostToolUseFailure" }))),
        Ok(None)
    );
    // A blank or non-string field is skipped; the next named field decides.
    assert_eq!(
        direct_event(&object(
            json!({ "event": "  ", "eventName": 3, "hookName": "Stop" })
        )),
        Ok(None)
    );
    assert_eq!(
        direct_event(&object(json!({ "event": "pretool", "hookName": "Stop" }))),
        Ok(Some("PreToolUse"))
    );
    assert_eq!(
        direct_event(&object(json!({ "event": "prétool" }))),
        Ok(None)
    );
}

#[test]
fn workspace_strings_normalize_like_the_daemon() {
    let normalized = |value: &str| normalized_workspace(Some(value), HOME);
    assert_eq!(
        normalized(" /work/./repo/ "),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/a/../repo"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("~/repo"),
        Ok(Some("/home/guard/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/repo/None"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/repo//None"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(normalized("/None"), Ok(Some("/".to_owned())));
    for absent in ["", "  ", "none", "NULL", "None"] {
        assert_eq!(normalized(absent), Ok(None), "{absent:?}");
    }
    assert_eq!(normalized_workspace(None, HOME), Ok(None));
    for invalid in [
        "relative/repo",
        "~other/repo",
        "//work/repo",
        "/work\u{1f}repo",
    ] {
        assert_eq!(
            normalized(invalid),
            Err(HookDirectDefer::WorkspaceInvalid),
            "{invalid:?}"
        );
    }
    assert_eq!(normpath("///work//repo"), Ok("/work/repo".to_owned()));
    assert_eq!(expanduser("~", HOME), Ok(HOME.to_owned()));
}

#[test]
fn workspace_prefers_exec_command_workdir_then_cwd_then_query() {
    let payload = object(json!({
        "tool_name": " Exec_Command ",
        "tool_input": { "workdir": "/work/action" },
        "cwd": "/work/cwd",
    }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/action".to_owned()))
    );
    let payload = object(json!({ "tool_name": "read_file", "cwd": "/work/cwd" }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/cwd".to_owned()))
    );
    let payload = object(json!({ "cwd": "None" }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/query".to_owned()))
    );
    assert_eq!(
        workspace_candidate(&object(json!({})), None, HOME),
        Ok(None)
    );
    // The daemon rejects a present but unusable workdir instead of skipping it.
    for workdir in [json!(null), json!(""), json!("none"), json!(7)] {
        let payload = object(json!({
            "tool_name": "exec_command",
            "tool_input": { "workdir": workdir },
            "cwd": "/work/cwd",
        }));
        assert_eq!(
            workspace_candidate(&payload, None, HOME),
            Err(HookDirectDefer::WorkspaceInvalid)
        );
    }
}
