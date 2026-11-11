use serde_json::{json, Value};

use super::{consumer_base_url, dispatch};
use crate::runner_authority_op::ERR_INVALID;

fn ask(request: Value) -> Value {
    dispatch(&request).expect("answer")
}

#[test]
fn servers_keep_user_entries_and_add_the_overlay() {
    let answer = ask(json!({
        "op": "servers",
        "names": ["user", "guard-old", null, "guard-user-owned", "guard-a"],
        "managed": ["guard-old", "guard-a"],
        "overlay": ["a", "b"],
    }));
    assert_eq!(answer["keep"], json!([0, 3]));
    assert_eq!(answer["add"], json!(["guard-a", "guard-b"]));

    let uninstall = ask(json!({
        "op": "servers", "names": ["guard-a", "user"], "managed": ["guard-a"], "overlay": [],
    }));
    assert_eq!(uninstall, json!({"keep": [1], "add": []}));
}

#[test]
fn overlay_names_scope_a_taken_name() {
    let answer = ask(json!({
        "op": "overlay_names",
        "servers": [
            ["yaml:fs", "fs"],
            ["json:fs", "fs"],
            ["json:fs-x", "json-fs"],
            ["json:fs", "fs"],
            ["yaml:git", null],
            ["yaml:empty", ""],
        ],
    }));
    assert_eq!(
        answer["names"],
        json!([
            "fs",
            "json-fs",
            "json-fs-x",
            "json-fs-2",
            "yaml:git",
            "yaml:empty"
        ])
    );
}

#[test]
fn the_guard_section_keeps_its_key_order() {
    let answer = ask(
        json!({"op": "guard_section", "base_url": "https://h/api/v1/consumer", "timeout_seconds": 5}),
    );
    let keys: Vec<&str> = answer["section"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| pair[0].as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        [
            "enabled",
            "base_url",
            "timeout_seconds",
            "cache_ttl_seconds",
            "fail_open",
            "token_env_var",
            "enforce_mcp_tools",
            "pain_signals_enabled",
        ]
    );
    assert_eq!(answer["section"][1][1], "https://h/api/v1/consumer");
    assert_eq!(answer["section"][2][1], 5);
    assert_eq!(answer["section"][4][1], false);
}

#[test]
fn the_consumer_url_follows_the_issuer_origin() {
    for (issuer, expected) in [
        (
            Some("https://staging.example.test"),
            "https://staging.example.test/api/v1/consumer",
        ),
        (
            Some("  HTTPS://Host.example:8443/path?q#f "),
            "https://Host.example:8443/api/v1/consumer",
        ),
        (
            Some("http://user@h\tost/x"),
            "http://user@host/api/v1/consumer",
        ),
        (Some("http://[::1]:9/"), "http://[::1]:9/api/v1/consumer"),
        (Some("http://[::1/"), "https://hol.org/api/v1/consumer"),
        (Some("host.example"), "https://hol.org/api/v1/consumer"),
        (Some("https:/host"), "https://hol.org/api/v1/consumer"),
        (Some("1http://host"), "https://hol.org/api/v1/consumer"),
        (Some("https://"), "https://hol.org/api/v1/consumer"),
        (Some("   "), "https://hol.org/api/v1/consumer"),
        (None, "https://hol.org/api/v1/consumer"),
    ] {
        assert_eq!(consumer_base_url(issuer), expected, "{issuer:?}");
        assert_eq!(
            ask(json!({"op": "consumer_base_url", "issuer": issuer}))["base_url"],
            expected
        );
    }
}

#[test]
fn install_state_reports_new_managed_and_repaired_installs() {
    for (empty, overlay, pretool, expected) in [
        (true, false, false, "installed"),
        (false, true, true, "already_managed"),
        (false, true, false, "repaired_managed_install"),
        (false, false, true, "repaired_managed_install"),
    ] {
        let answer = ask(json!({
            "op": "install_state",
            "manifest_empty": empty,
            "overlay_exists": overlay,
            "pretool_exists": pretool,
        }));
        assert_eq!(answer["state"], expected);
    }
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({"op": "servers", "names": [1], "managed": [], "overlay": []}),
        json!({"op": "servers", "names": [], "managed": [], "overlay": [], "extra": 1}),
        json!({"op": "overlay_names", "servers": [["k"]]}),
        json!({"op": "overlay_names", "servers": [["k", 1]]}),
        json!({"op": "consumer_base_url", "issuer": 1}),
        json!({"op": "guard_section", "base_url": null, "timeout_seconds": 5}),
        json!({"op": "guard_section", "base_url": "u", "timeout_seconds": -1}),
        json!({"op": "install_state", "manifest_empty": true, "overlay_exists": 1, "pretool_exists": true}),
        json!({"op": "other"}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
