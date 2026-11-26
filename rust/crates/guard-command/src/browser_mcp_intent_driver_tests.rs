use guard_contracts::{BrowserIntentV1, BrowserSensitiveSurfaceV1};
use serde_json::{json, Value};

use super::*;

fn intent(server: &str, tool: &str, arguments: Value) -> Option<BrowserAutomationIntentV1> {
    let artifact = BrowserMcpArtifactV1 {
        name: tool.to_owned(),
        command: Some(tool.to_owned()),
        metadata: json!({"server_name": server}).as_object().cloned().unwrap(),
    };
    normalize_approval_intent(&artifact, &arguments).expect("normalizes")
}

#[test]
fn a_bare_puppeteer_server_is_a_browser_server_for_every_listed_tool() {
    for (tool, expected) in [
        ("puppeteer_navigate", BrowserIntentV1::Navigation),
        ("puppeteer_screenshot", BrowserIntentV1::Inspect),
        ("puppeteer_click", BrowserIntentV1::Interact),
        ("puppeteer_hover", BrowserIntentV1::Interact),
        ("puppeteer_fill", BrowserIntentV1::Interact),
        ("puppeteer_select", BrowserIntentV1::Interact),
        ("puppeteer_evaluate", BrowserIntentV1::Privileged),
        ("puppeteer_connect_active_tab", BrowserIntentV1::Privileged),
    ] {
        let found = intent("puppeteer", tool, json!({})).unwrap_or_else(|| panic!("{tool}"));
        assert_eq!(found.intent, expected, "{tool}");
    }
}

#[test]
fn the_bare_name_only_matches_the_whole_server_name() {
    assert!(intent("puppeteerish", "puppeteer_fill", json!({})).is_none());
    assert!(intent("notes", "puppeteer_fill", json!({})).is_none());
}

#[test]
fn a_navigate_that_passes_launch_options_is_raw_protocol_access() {
    let plain = intent(
        "puppeteer",
        "puppeteer_navigate",
        json!({"url": "https://example.com/"}),
    )
    .unwrap();
    assert!(!plain
        .sensitive_surface_flags
        .contains(&BrowserSensitiveSurfaceV1::Cdp));
    for arguments in [
        json!({"url": "https://example.com/", "launchOptions": {"headless": false}}),
        json!({"url": "https://example.com/", "allowDangerous": true}),
    ] {
        let relaunch = intent("puppeteer", "puppeteer_navigate", arguments).unwrap();
        assert!(relaunch
            .sensitive_surface_flags
            .contains(&BrowserSensitiveSurfaceV1::Cdp));
    }
}

#[test]
fn a_launch_option_named_only_in_the_description_or_a_longer_key_is_not_raw_protocol_access() {
    let artifact = BrowserMcpArtifactV1 {
        name: "puppeteer_navigate".to_owned(),
        command: Some("puppeteer_navigate".to_owned()),
        metadata: json!({"server_name": "puppeteer",
            "tool_description": "Navigate to a URL. Pass launchOptions to relaunch the browser."})
        .as_object()
        .cloned()
        .unwrap(),
    };
    for arguments in [
        json!({"url": "https://example.com/"}),
        json!({"url": "https://example.com/", "launchOptionsDocumentation": "see readme"}),
    ] {
        let found = normalize_approval_intent(&artifact, &arguments)
            .expect("normalizes")
            .unwrap();
        assert!(!found
            .sensitive_surface_flags
            .contains(&BrowserSensitiveSurfaceV1::Cdp));
    }
}

#[test]
fn browsermcp_runs_a_command_script_as_privileged() {
    let script = intent(
        "browsermcp",
        "browser",
        json!({"commands": "goto https://example.com/\nsnapshot"}),
    )
    .expect("browser server");
    assert_eq!(script.intent, BrowserIntentV1::Privileged);
    let navigate = intent(
        "browsermcp",
        "browser_navigate",
        json!({"url": "https://example.com/"}),
    )
    .unwrap();
    assert_eq!(navigate.intent, BrowserIntentV1::Navigation);
}
