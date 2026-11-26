use serde_json::json;

use super::*;
use crate::mcp_tool_risk::evaluate_tool_risk;

struct Home(std::path::PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str, port: u16) -> Home {
    let root = std::env::temp_dir().join(format!("guard-origin-{name}-{}", std::process::id()));
    let guard = root.join(".hol-guard");
    std::fs::create_dir_all(&guard).unwrap();
    std::fs::write(
        guard.join("daemon-state.json"),
        format!("{{\"port\": {port}}}"),
    )
    .unwrap();
    Home(root)
}

#[test]
fn every_loopback_spelling_of_the_daemon_port_is_guard_origin() {
    let home = home("spellings", 51234);
    let home = home.0.to_str();
    for target in [
        "http://localhost:51234/approvals",
        "http://LOCALHOST:51234/",
        "http://localhost.:51234/",
        "http://app.localhost:51234/",
        "http://127.0.0.1:51234/",
        "http://127.1:51234/",
        "http://2130706433:51234/",
        "http://0x7f000001:51234/",
        "http://0x7f.0.0.1:51234/",
        "http://0177.0.0.1:51234/",
        "http://[::1]:51234/",
        "http://[::ffff:127.0.0.1]:51234/",
        "http://0.0.0.0:51234/",
        "ws://localhost:51234/events",
        " https://localhost:51234/ ",
    ] {
        assert!(is_guard_origin(target, home), "{target}");
    }
}

#[test]
fn other_ports_hosts_and_schemes_are_not() {
    let home = home("others", 51234);
    let home = home.0.to_str();
    for target in [
        "http://localhost:5173/",
        "http://localhost:51235/",
        "http://example.com:51234/",
        "http://localhost.example.com:51234/",
        "http://10.0.0.1:51234/",
        "file:///tmp/page.html",
        "javascript:alert(1)",
        "not a url",
    ] {
        assert!(!is_guard_origin(target, home), "{target}");
    }
}

#[test]
fn without_a_recorded_port_the_default_port_counts() {
    let root = std::env::temp_dir().join(format!("guard-origin-default-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let home = Home(root);
    let home = home.0.to_str();
    if std::env::var_os("GUARD_DAEMON_PORT").is_some()
        || std::env::var_os("HOL_GUARD_HOME").is_some()
    {
        return;
    }
    assert!(is_guard_origin("http://localhost:4781/", home));
    assert!(!is_guard_origin("http://localhost:5173/", home));
}

fn artifact(tool: &str, page: Option<&str>) -> guard_contracts::BrowserMcpArtifactV1 {
    let mut metadata = serde_json::Map::new();
    metadata.insert("server_name".to_owned(), json!("playwright"));
    if let Some(page) = page {
        metadata.insert("browser_current_page_url".to_owned(), json!(page));
    }
    guard_contracts::BrowserMcpArtifactV1 {
        name: format!("playwright:{tool}"),
        command: Some(tool.to_owned()),
        metadata,
    }
}

#[test]
fn a_redirected_page_on_the_approval_center_is_guard_origin() {
    let guard_page = "http://localhost:4781/approvals/pending";
    if std::env::var_os("GUARD_DAEMON_PORT").is_some()
        || std::env::var_os("HOL_GUARD_HOME").is_some()
        || is_guard_origin("http://localhost:1/", None)
        || !is_guard_origin(guard_page, None)
    {
        return;
    }
    let clicked = evaluate_tool_risk(
        &artifact("browser_click", Some(guard_page)),
        &json!({"element": "Approve", "ref": "e7"}),
    )
    .unwrap();
    assert!(clicked.iter().any(|name| name == "browser_guard_origin"));
    let opened = evaluate_tool_risk(
        &artifact("browser_navigate", None),
        &json!({"url": "http://127.0.0.1:4781/"}),
    )
    .unwrap();
    assert!(opened.iter().any(|name| name == "browser_guard_origin"));
    let elsewhere = evaluate_tool_risk(
        &artifact("browser_navigate", None),
        &json!({"url": "https://example.com/"}),
    )
    .unwrap();
    assert!(!elsewhere.iter().any(|name| name == "browser_guard_origin"));
}

#[test]
fn the_reason_text_never_carries_the_approval_url() {
    let text = crate::mcp_tool_signals::guard_origin_signal_for_test();
    assert!(text.contains("approval center"), "{text}");
    assert!(!text.contains("http"), "{text}");
    assert!(!text.contains("4781"), "{text}");
}
