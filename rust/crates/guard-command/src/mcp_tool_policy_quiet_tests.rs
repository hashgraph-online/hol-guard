use super::*;

fn browser_request(
    tool: &str,
    arguments: Value,
    page: Option<&str>,
    args: &[&str],
    config: Value,
) -> McpToolPolicyRequestV1 {
    let mut metadata = serde_json::json!({"server_name": "playwright",
        "mcp_tool_identity": {"tool_name": tool}, "args": args});
    if let Some(page) = page {
        metadata["browser_current_page_url"] = serde_json::json!(page);
    }
    serde_json::from_value(serde_json::json!({
        "artifact": {"name": format!("playwright:{tool}"), "command": tool, "metadata": metadata},
        "arguments": arguments,
        "config": config,
        "harness": "codex", "artifact_id": format!("playwright:{tool}"), "publisher": null,
    }))
    .unwrap()
}

#[test]
fn loopback_dev_pages_are_quiet_under_a_stricter_default() {
    use crate::browser_guard_origin::tests::{guard_home, with_guard_home};
    let home = guard_home("policy-quiet", Some(51234));
    let config = || serde_json::json!({"mode": "prompt", "default_action": "block"});
    let decide = |request: McpToolPolicyRequestV1| {
        with_guard_home(&home.0, || evaluate_tool_policy(&request).unwrap())
    };
    let local = "http://127.0.0.1:4173/";
    let click = serde_json::json!({"element": "Save", "ref": "e3"});

    let quiet = decide(browser_request(
        "browser_click",
        click.clone(),
        Some(local),
        &["--isolated"],
        config(),
    ));
    assert_eq!(
        (quiet.action.as_str(), quiet.source.as_str()),
        ("allow", "browser-loopback-quiet")
    );
    let navigate = decide(browser_request(
        "browser_navigate",
        serde_json::json!({"url": "http://localhost:3000/"}),
        None,
        &["--user-data-dir=/tmp/p"],
        config(),
    ));
    assert_eq!(navigate.action, "allow");

    // Each exclusion keeps the default's decision.
    let admin = decide(browser_request(
        "browser_click",
        click.clone(),
        Some("http://127.0.0.1:8001/"),
        &["--isolated"],
        config(),
    ));
    assert_eq!(admin.action, "block");
    let shared = decide(browser_request(
        "browser_click",
        click.clone(),
        Some(local),
        &["--shared"],
        config(),
    ));
    assert_eq!(shared.action, "block");
    let unknown = decide(browser_request(
        "browser_click",
        click.clone(),
        Some(local),
        &[],
        config(),
    ));
    assert_eq!(unknown.action, "block");
    let debugging = decide(browser_request(
        "browser_click",
        click.clone(),
        Some("http://127.0.0.1:3001/"),
        &["--isolated", "--cdp-endpoint=http://127.0.0.1:3001"],
        config(),
    ));
    assert_eq!(debugging.action, "block");
    let unknown_page = decide(browser_request(
        "browser_click",
        click.clone(),
        None,
        &["--isolated"],
        config(),
    ));
    assert_eq!(unknown_page.action, "block");

    // A stricter action the user set for this artifact still applies.
    let pinned = decide(browser_request(
        "browser_click",
        click,
        Some(local),
        &["--isolated"],
        serde_json::json!({"mode": "prompt", "default_action": "allow",
            "artifact_actions": {"playwright:browser_click": "review"}}),
    ));
    assert_eq!(
        (pinned.action.as_str(), pinned.summary_code.as_str()),
        ("review", "configuration_stricter")
    );
}

/// The relay sends no `args`; its launch reaches the policy only as `server_fingerprint.command`.
fn relay_request(tool: &str, arguments: Value, command: &[&str]) -> McpToolPolicyRequestV1 {
    let metadata = serde_json::json!({"server_name": "playwright",
        "mcp_tool_identity": {"tool_name": tool},
        "mcp_server_identity": {"args_hash": "0".repeat(64)},
        "server_fingerprint": {"command": command, "transport": "stdio"}});
    serde_json::from_value(serde_json::json!({
        "artifact": {"name": format!("playwright:{tool}"), "command": tool, "metadata": metadata},
        "arguments": arguments,
        "config": {"mode": "prompt", "default_action": "block"},
        "harness": "codex", "artifact_id": format!("playwright:{tool}"), "publisher": null,
    }))
    .unwrap()
}

#[test]
fn a_relayed_isolated_launch_is_read_from_the_server_fingerprint() {
    use crate::browser_guard_origin::tests::{guard_home, with_guard_home};
    let home = guard_home("policy-quiet-relay", Some(51235));
    let decide = |request: McpToolPolicyRequestV1| {
        with_guard_home(&home.0, || evaluate_tool_policy(&request).unwrap())
    };
    let navigate = serde_json::json!({"url": "http://127.0.0.1:4173/"});
    let isolated = decide(relay_request(
        "browser_navigate",
        navigate.clone(),
        &["npx", "@playwright/mcp@latest", "--isolated"],
    ));
    assert_eq!(
        (isolated.action.as_str(), isolated.source.as_str()),
        ("allow", "browser-loopback-quiet")
    );
    // The executable is not an argument, and an unflagged launch stays unknown.
    let unflagged = decide(relay_request(
        "browser_navigate",
        navigate.clone(),
        &["--isolated"],
    ));
    assert_eq!(unflagged.action, "block");
    let debugging = decide(relay_request(
        "browser_navigate",
        serde_json::json!({"url": "http://127.0.0.1:3000/"}),
        &[
            "npx",
            "@playwright/mcp@latest",
            "--isolated",
            "--cdp-endpoint=http://127.0.0.1:3000",
        ],
    ));
    assert_eq!(debugging.action, "block");
    // An unsupported flag that only starts like an isolation flag does not outrank `--shared`.
    let conflicting = decide(relay_request(
        "browser_navigate",
        navigate.clone(),
        &[
            "npx",
            "@playwright/mcp@latest",
            "--isolated-profile-cache",
            "--shared",
        ],
    ));
    assert_eq!(conflicting.action, "block");
    let shared_beside_isolated = decide(relay_request(
        "browser_navigate",
        navigate.clone(),
        &["npx", "@playwright/mcp@latest", "--isolated", "--shared"],
    ));
    assert_eq!(shared_beside_isolated.action, "block");
    let userinfo = decide(relay_request(
        "browser_navigate",
        serde_json::json!({"url": "http://dev:pw@127.0.0.1:4173/"}),
        &["npx", "@playwright/mcp@latest", "--isolated"],
    ));
    assert_eq!(userinfo.action, "block");
}
