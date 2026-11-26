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
    // The relay renders evidence from the verdict's summary code; an unknown code fails the
    // whole decision.
    let artifact =
        browser_request("browser_click", click.clone(), Some(local), &[], config()).artifact;
    let input: guard_contracts::McpToolRiskInputV1 = serde_json::from_value(serde_json::json!({
        "artifact": artifact,
        "arguments": {"format": "other", "value": click.clone()},
        "risk_categories": quiet.risk_categories.clone(),
        "summary_code": quiet.summary_code.clone(),
    }))
    .unwrap();
    let evidence = crate::mcp_tool_signals::evaluate_risk_evidence(&input).unwrap();
    assert!(evidence["summary"]
        .as_str()
        .unwrap()
        .contains("local development server"));
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

#[test]
fn quiet_needs_a_known_destination_and_reads_all_of_loopback() {
    use crate::browser_guard_origin::tests::{guard_home, with_guard_home};
    let home = guard_home("policy-quiet-destination", Some(51234));
    let config = || serde_json::json!({"mode": "prompt", "default_action": "block"});
    let decide = |request: McpToolPolicyRequestV1| {
        with_guard_home(&home.0, || evaluate_tool_policy(&request).unwrap())
    };
    let local = "http://127.0.0.1:4173/";

    // A history step leaves the reported page; where it lands is unknown, so it is never quiet.
    let back = decide(browser_request(
        "browser_navigate_back",
        serde_json::json!({}),
        Some(local),
        &["--isolated"],
        config(),
    ));
    assert_eq!(back.action, "block");
    // A reload lands on the page it reloads.
    let reload = decide(browser_request(
        "browser_reload",
        serde_json::json!({}),
        Some(local),
        &["--isolated"],
        config(),
    ));
    assert_eq!(
        (reload.action.as_str(), reload.source.as_str()),
        ("allow", "browser-loopback-quiet")
    );

    // Every 127.0.0.0/8 address is loopback, not an external domain.
    let other_loopback = decide(browser_request(
        "browser_navigate",
        serde_json::json!({"url": "http://127.0.0.2:4173/"}),
        None,
        &["--isolated"],
        config(),
    ));
    assert_eq!(other_loopback.action, "allow");
    assert!(!other_loopback
        .risk_categories
        .iter()
        .any(|category| category == "browser_external_domain"));

    // A token hidden behind percent-encoding is still a secret-shaped URL.
    let encoded = "%61".repeat(64);
    let hidden = decide(browser_request(
        "browser_navigate",
        serde_json::json!({"url": format!("http://127.0.0.1:4173/{encoded}")}),
        None,
        &["--isolated"],
        config(),
    ));
    assert_eq!(hidden.action, "block");
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
