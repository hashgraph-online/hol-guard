use serde_json::{json, Value};

use crate::cline_install_plan::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const MCP_PROXY_VECTORS: &str = include_str!("../../testdata/cline/mcp_proxy_vectors.json");

fn transport(surface: &str, frozen: bool, cli: bool, vscode: bool, jetbrains: bool) -> Value {
    dispatch(&json!({
        "op": "transport",
        "surface": surface,
        "frozen": frozen,
        "cli": cli,
        "vscode": vscode,
        "jetbrains": jetbrains,
    }))
    .expect("transport answer")
}

fn reconcile(target_ready: bool, other_installed: bool, other_ready: bool) -> Value {
    dispatch(&json!({
        "op": "reconcile",
        "target_ready": target_ready,
        "other_installed": other_installed,
        "other_ready": other_ready,
    }))
    .expect("reconcile answer")
}

fn posture(transport: &str, hook_ready: bool, plugin_ready: bool, jetbrains: bool) -> Value {
    dispatch(&json!({
        "op": "posture",
        "transport": transport,
        "hook_ready": hook_ready,
        "plugin_ready": plugin_ready,
        "jetbrains": jetbrains,
    }))
    .expect("posture answer")
}

#[test]
fn explicit_surfaces_keep_their_transport_without_fallback() {
    assert_eq!(
        transport("plugin", false, false, true, true),
        json!({"transport": "plugin", "fallback": false})
    );
    assert_eq!(
        transport("hooks", true, true, false, false),
        json!({"transport": "hooks", "fallback": false})
    );
}

#[test]
fn frozen_runtime_and_cli_only_hosts_take_the_plugin() {
    for surface in ["auto", "all", "cli"] {
        assert_eq!(
            transport(surface, true, false, true, true),
            json!({"transport": "plugin", "fallback": true})
        );
        assert_eq!(
            transport(surface, false, true, false, false),
            json!({"transport": "plugin", "fallback": true})
        );
    }
}

#[test]
fn editor_hosts_take_native_hooks() {
    assert_eq!(
        transport("auto", false, true, true, false),
        json!({"transport": "hooks", "fallback": false})
    );
    assert_eq!(
        transport("auto", false, true, false, true),
        json!({"transport": "hooks", "fallback": false})
    );
    assert_eq!(
        transport("all", false, false, false, false),
        json!({"transport": "hooks", "fallback": false})
    );
}

#[test]
fn reconcile_removes_the_other_transport_once_it_is_safe() {
    assert_eq!(
        reconcile(false, false, false),
        json!({"remove_other": false, "transition_pending": false})
    );
    assert_eq!(
        reconcile(true, true, true),
        json!({"remove_other": true, "transition_pending": false})
    );
    assert_eq!(
        reconcile(false, true, false),
        json!({"remove_other": true, "transition_pending": false})
    );
    assert_eq!(
        reconcile(false, true, true),
        json!({"remove_other": false, "transition_pending": true})
    );
}

#[test]
fn posture_labels_each_transport() {
    assert_eq!(
        posture("plugin", false, true, false),
        json!({"coverage": "full", "blind_spots": []})
    );
    assert_eq!(
        posture("plugin", true, false, false),
        json!({"coverage": "pending-live-proof", "blind_spots": []})
    );
    let hooks = posture("hooks", true, false, true);
    assert_eq!(hooks["coverage"], "pre-execution");
    assert_eq!(hooks["blind_spots"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        posture("hooks", false, true, true)["coverage"],
        "unverified"
    );
    assert_eq!(
        posture("hooks", false, true, false)["coverage"],
        "pending-live-proof"
    );
}

#[test]
fn malformed_requests_are_refused() {
    let refused = [
        json!({"op": "transport", "surface": "editor", "frozen": false, "cli": false, "vscode": false, "jetbrains": false}),
        json!({"op": "transport", "surface": "auto", "frozen": false, "cli": false, "vscode": false}),
        json!({"op": "reconcile", "target_ready": 1, "other_installed": false, "other_ready": false}),
        json!({"op": "posture", "transport": "cli", "hook_ready": false, "plugin_ready": false, "jetbrains": false}),
        json!({"op": "posture", "transport": "hooks", "hook_ready": false, "plugin_ready": false, "jetbrains": false, "extra": true}),
        json!({"op": "mcp_proxy"}),
        json!({"op": "mcp_proxy", "settings": 1}),
        json!({"op": "mcp_proxy", "settings": "{}", "extra": true}),
        json!({"op": "mcp_proxy", "settings": "[]"}),
        json!({"op": "mcp_proxy", "settings": "{"}),
        json!({"op": "mcp_proxy", "settings": r#"{"a\ud800": "\udb80\udc00"}"#}),
        json!({"op": "unknown"}),
        json!([]),
    ];
    for request in refused {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

fn mcp_proxy(settings: &str) -> String {
    let answer = dispatch(&json!({"op": "mcp_proxy", "settings": settings})).expect("mcp answer");
    answer["plan"].as_str().expect("plan text").to_owned()
}

#[test]
fn mcp_proxy_plans_match_the_python_vectors() {
    let vectors: Value = serde_json::from_str(MCP_PROXY_VECTORS).expect("vectors");
    for case in vectors.as_array().expect("cases") {
        assert_eq!(
            mcp_proxy(case["settings"].as_str().expect("settings")),
            case["expected"].as_str().expect("expected"),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn mcp_proxy_lone_surrogates_reach_python_intact() {
    assert_eq!(
        mcp_proxy(r#"{"mcpServers": {"a\ud800": {"command": "x", "env": {"K": "v\udc00"}}}}"#),
        r#"{"key":"mcpServers","managed":[{"name":"a\ud800","command":"x","args":[],"transport":"stdio","env":{"K":"v\udc00"}}],"remote":[]}"#
    );
    assert_eq!(
        mcp_proxy(r#"{"mcpServers": {"r\udfff": {"type": "sse"}}}"#),
        r#"{"key":"mcpServers","managed":[],"remote":["r\udfff"]}"#
    );
}

#[test]
fn mcp_proxy_keeps_private_use_characters_without_a_lone_surrogate() {
    assert_eq!(
        mcp_proxy(r#"{"mcpServers": {"\udb80\udc00": {"command": "x"}}}"#),
        "{\"key\":\"mcpServers\",\"managed\":[{\"name\":\"\u{f0000}\",\"command\":\"x\",\"args\":[],\"transport\":\"stdio\",\"env\":{}}],\"remote\":[]}"
    );
}
