use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn adapters() -> Value {
    json!([
        ["claude-code", "claude", ["claude-code"]],
        ["cursor", "cursor-agent", ["cursor"]],
        ["other", "claude", []],
        ["codex", "codex", []],
    ])
}

fn plan(entries: Value) -> Vec<Value> {
    let answer = dispatch(&json!({"op": "plan", "entries": entries, "adapters": adapters()}))
        .expect("answer");
    answer["steps"].as_array().unwrap().clone()
}

fn context(body: &str, install_workspace: Value) -> Value {
    dispatch(&json!({"op": "context", "body": body, "install_workspace": install_workspace}))
        .expect("answer")
}

#[test]
fn the_plan_visits_guard_shims_in_name_order() {
    let steps = plan(json!([
        "guard-codex",
        "guard-codex.cmd",
        "notes.txt",
        "guard-claude",
        "guard-gone",
    ]));
    assert_eq!(
        steps,
        [
            json!({"name": "claude", "action": "check", "harness": "claude-code", "canonical": "claude", "legacy": false}),
            json!({"name": "codex", "action": "check", "harness": "codex", "canonical": "codex", "legacy": false}),
            json!({"name": "gone", "action": "unknown"}),
        ]
    );
}

#[test]
fn a_legacy_shim_is_dropped_only_beside_its_canonical_one() {
    let steps = plan(json!([
        "guard-cursor",
        "guard-cursor-agent",
        "guard-claude-code"
    ]));
    assert_eq!(steps[0]["name"], "claude-code");
    assert_eq!(steps[0]["action"], "check");
    assert_eq!(steps[0]["legacy"], true);
    assert_eq!(steps[0]["canonical"], "claude");
    assert_eq!(steps[1]["name"], "cursor");
    assert_eq!(steps[1]["action"], "drop_legacy");
    assert_eq!(steps[2]["name"], "cursor-agent");
    assert_eq!(steps[2]["action"], "check");
}

#[test]
fn the_installed_context_comes_from_base_command() {
    let body = "#!/usr/bin/env python3\nbase_command = ['/py', '-m', 'x', '--home', '/h', '--workspace', '/w']\nbase_command = ['--home', '/later']\n";
    assert_eq!(
        context(body, json!("/recorded")),
        json!({"recognized": true, "home": "/h", "workspace": "/w"})
    );
    let commented = "@echo off\r\n# base_command = [\"/py\", \"--home\"]\r\n";
    assert_eq!(
        context(commented, json!("/recorded")),
        json!({"recognized": true, "home": null, "workspace": "/recorded"})
    );
    let plain = "base_command = ['/py']";
    assert_eq!(context(plain, json!("  "))["workspace"], Value::Null);
    assert_eq!(context(plain, Value::Null)["workspace"], Value::Null);
}

#[test]
fn an_unparseable_base_command_is_unrecognized() {
    for body in [
        "",
        "#!/bin/sh\nexec guard\n",
        "base_command = ['/py', 1]\nbase_command = ['/py']\n",
        "base_command = '/py'",
        "  base_command = ['/py']",
    ] {
        assert_eq!(
            context(body, Value::Null),
            json!({"recognized": false, "home": null, "workspace": null}),
            "{body:?}"
        );
    }
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({"op": "plan", "entries": [1], "adapters": []}),
        json!({"op": "plan", "entries": [], "adapters": [["h", "l"]]}),
        json!({"op": "plan", "entries": [], "adapters": [["h", "l", [1]]]}),
        json!({"op": "plan", "entries": [], "adapters": [], "extra": 1}),
        json!({"op": "context", "body": 1, "install_workspace": null}),
        json!({"op": "context", "body": "", "install_workspace": 1}),
        json!({"op": "context", "body": ""}),
        json!({"op": "other"}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
