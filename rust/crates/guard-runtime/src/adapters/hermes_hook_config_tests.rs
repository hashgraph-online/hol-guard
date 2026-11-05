//! Pins the `hermes_hook_config` answers the Hermes adapter applies.

use serde_json::{json, Value};

use crate::hermes_hook_config::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const COMMAND: &str = "/usr/bin/python3 -I /opt/guard/pretool-hook.py";

fn cwd() -> String {
    std::env::temp_dir().to_string_lossy().into_owned()
}

fn plan(entries: Value, expected: Option<&str>) -> Value {
    dispatch(&json!({
        "op": "pretool_plan",
        "entries": entries,
        "expected_command": expected,
        "cwd": cwd(),
    }))
    .expect("plan")
}

fn guard_entry(command: &str) -> Value {
    json!({"id": "hol-guard-pretool", "matcher": ".*", "command": command, "fail_closed": true})
}

#[test]
fn merge_drops_guard_entries_and_keeps_user_hooks() {
    let entries = json!([
        {"id": "user", "command": "echo user"},
        guard_entry("old guard command"),
        {"command": COMMAND},
        "not a mapping",
        {"command": "/usr/bin/python3 -c 'import bounded_cli_hook_bridge'"},
        {"command": "hol-guard __guard-bounded-hook hermes"},
    ]);
    assert_eq!(
        plan(entries, Some(COMMAND)),
        json!({
            "keep": [0, 3],
            "removed": [
                "old guard command",
                COMMAND,
                "/usr/bin/python3 -c 'import bounded_cli_hook_bridge'",
                "hol-guard __guard-bounded-hook hermes",
            ],
        })
    );
}

#[test]
fn uninstall_keeps_an_entry_matched_only_by_the_expected_command() {
    let entries = json!([{"command": COMMAND}, guard_entry(" ")]);
    assert_eq!(plan(entries, None), json!({"keep": [0], "removed": []}));
}

#[test]
fn a_marker_substring_alone_is_not_a_guard_command() {
    let entries = json!([
        {"command": "echo __guard-bounded-hook-extra"},
        {"command": "python3 -c 'print(1)' bounded_cli_hook_bridge"},
        {"command": "echo 'unclosed"},
        {"command": 7},
    ]);
    assert_eq!(
        plan(entries, Some(COMMAND)),
        json!({"keep": [0, 1, 2, 3], "removed": []})
    );
}

#[test]
fn an_isolated_script_matches_only_the_same_resolved_script() {
    let entries = json!([
        {"command": "/other/python -I /opt/guard/../guard/pretool-hook.py"},
        {"command": "/usr/bin/python3 -I /opt/guard/other.py"},
        {"command": "/usr/bin/python3 -I /opt/guard/pretool-hook.py extra"},
    ]);
    assert_eq!(
        plan(entries.clone(), Some(COMMAND)),
        json!({"keep": [1, 2], "removed": ["/other/python -I /opt/guard/../guard/pretool-hook.py"]})
    );
    assert_eq!(
        plan(entries.clone(), None),
        json!({"keep": [0, 1, 2], "removed": []})
    );
    let without_cwd = dispatch(&json!({
        "op": "pretool_plan",
        "entries": entries,
        "expected_command": COMMAND,
        "cwd": null,
    }))
    .expect("plan without cwd");
    assert_eq!(without_cwd, json!({"keep": [0, 1, 2], "removed": []}));
}

fn registered(entries: Value, approvals: Value) -> Value {
    dispatch(&json!({
        "op": "registered",
        "entries": entries,
        "expected_command": null,
        "approvals": approvals,
    }))
    .expect("registered")["registered"]
        .clone()
}

#[test]
fn registration_needs_fail_closed_match_all_and_an_approval() {
    let approval = json!([{"event": "pre_tool_call", "command": COMMAND}]);
    assert_eq!(
        registered(json!([guard_entry(COMMAND)]), approval.clone()),
        json!(true)
    );
    assert_eq!(
        registered(json!([guard_entry(COMMAND)]), json!(null)),
        json!(true)
    );
    let camel = json!([{"id": "hol-guard-pretool", "matcher": ".*", "command": COMMAND, "failClosed": true}]);
    assert_eq!(registered(camel, approval.clone()), json!(true));
    let open = json!([{"id": "hol-guard-pretool", "matcher": ".*", "command": COMMAND, "fail_closed": false}]);
    assert_eq!(registered(open, approval.clone()), json!(false));
    let narrow = json!([{"id": "hol-guard-pretool", "matcher": "terminal", "command": COMMAND, "fail_closed": true}]);
    assert_eq!(registered(narrow, approval.clone()), json!(false));
    assert_eq!(
        registered(json!([guard_entry(COMMAND)]), json!([])),
        json!(false)
    );
    assert_eq!(
        registered(json!([guard_entry(COMMAND)]), json!(false)),
        json!(false)
    );
    assert_eq!(
        registered(json!([guard_entry(" ")]), json!(null)),
        json!(false)
    );
    let user = json!([{"id": "user", "matcher": ".*", "command": COMMAND, "fail_closed": true}]);
    assert_eq!(registered(user, approval), json!(false));
}

fn allowlist(approvals: Value, retire: Value, mode: &str) -> Value {
    dispatch(&json!({
        "op": "allowlist_plan",
        "approvals": approvals,
        "command": COMMAND,
        "retire": retire,
        "mode": mode,
    }))
    .expect("allowlist")
}

#[test]
fn merge_retires_old_commands_and_appends_once() {
    let approvals = json!([
        {"event": "pre_tool_call", "command": "old"},
        {"event": "post_tool_call", "command": "old"},
        "junk",
        {"event": "pre_tool_call", "command": "user"},
    ]);
    assert_eq!(
        allowlist(approvals, json!(["old", "", COMMAND]), "merge"),
        json!({"keep": [1, 3], "append": true})
    );
    let present = json!([{"event": "pre_tool_call", "command": COMMAND}]);
    assert_eq!(
        allowlist(present, json!([COMMAND]), "merge"),
        json!({"keep": [0], "append": false})
    );
}

#[test]
fn remove_drops_only_guard_approval() {
    let approvals = json!([
        {"event": "pre_tool_call", "command": COMMAND},
        {"event": "post_tool_call", "command": COMMAND},
        {"event": "pre_tool_call", "command": "user"},
        3,
    ]);
    assert_eq!(
        allowlist(approvals, json!(null), "remove"),
        json!({"keep": [1, 2], "append": false})
    );
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({"op": "pretool_plan", "entries": {}, "cwd": cwd()}),
        json!({"op": "pretool_plan", "entries": [], "cwd": "relative"}),
        json!({"op": "pretool_plan", "entries": [], "cwd": 1}),
        json!({"op": "pretool_plan", "entries": [], "expected_command": 1, "cwd": cwd()}),
        json!({"op": "registered", "entries": [], "approvals": true}),
        json!({"op": "allowlist_plan", "approvals": [], "command": COMMAND, "mode": "other"}),
        json!({"op": "allowlist_plan", "approvals": [], "command": COMMAND, "retire": [1], "mode": "merge"}),
        json!({"op": "unknown"}),
        json!([]),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
