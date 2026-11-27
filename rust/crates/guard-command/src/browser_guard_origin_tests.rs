use std::cell::RefCell;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;
use crate::mcp_tool_risk::evaluate_tool_risk;

thread_local! {
    static OVERRIDE_HOME: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// The Guard home [`is_guard_origin`] uses on this test thread, ignoring `GUARD_DAEMON_PORT`.
pub(super) fn override_home() -> Option<PathBuf> {
    OVERRIDE_HOME.with(|home| home.borrow().clone())
}

/// Run `body` with [`is_guard_origin`] reading `guard_home` on this thread.
pub(crate) fn with_guard_home<T>(guard_home: &Path, body: impl FnOnce() -> T) -> T {
    OVERRIDE_HOME.with(|home| *home.borrow_mut() = Some(guard_home.to_path_buf()));
    let result = body();
    OVERRIDE_HOME.with(|home| *home.borrow_mut() = None);
    result
}

/// A temporary Guard home, removed on drop.
pub(crate) struct GuardHome(pub(crate) PathBuf);

impl Drop for GuardHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A Guard home whose daemon state file records `port`, or none when `port` is `None`.
pub(crate) fn guard_home(name: &str, port: Option<u16>) -> GuardHome {
    let root = std::env::temp_dir().join(format!("guard-origin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    if let Some(port) = port {
        std::fs::write(
            root.join("daemon-state.json"),
            format!("{{\"port\": {port}}}"),
        )
        .unwrap();
    }
    GuardHome(root)
}

#[test]
fn every_loopback_spelling_of_the_daemon_port_is_guard_origin() {
    let home = guard_home("spellings", Some(51234));
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
        assert!(is_guard_origin_in(target, Some(&home.0), None), "{target}");
    }
}

#[test]
fn other_ports_hosts_and_schemes_are_not() {
    let home = guard_home("others", Some(51234));
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
        assert!(!is_guard_origin_in(target, Some(&home.0), None), "{target}");
    }
}

#[test]
fn the_default_port_the_env_port_and_the_recorded_port_all_count() {
    let home = guard_home("all-ports", Some(51234));
    let ports = guard_daemon_ports(Some(&home.0), Some(40000));
    assert_eq!(ports, vec![4781, 40000, 51234]);
    assert!(is_guard_origin_in(
        "http://localhost:40000/",
        Some(&home.0),
        Some(40000)
    ));
    assert!(is_guard_origin_in(
        "http://localhost:51234/",
        Some(&home.0),
        Some(40000)
    ));
    assert!(is_guard_origin_in(
        "http://localhost:4781/",
        Some(&home.0),
        Some(40000)
    ));
}

#[test]
fn without_a_recorded_port_the_whole_candidate_window_counts() {
    let home = guard_home("window", None);
    let ports = guard_daemon_ports(Some(&home.0), None);
    let window = candidate_window(&home.0);
    assert_eq!(window.len(), 25);
    assert!(window.iter().all(|port| (4781..=5780).contains(port)));
    assert!(window.iter().all(|port| ports.contains(port)));
    assert!(ports.contains(&4781));
    let outside = (4781..=5780).find(|port| !ports.contains(port)).unwrap();
    assert!(!is_guard_origin_in(
        &format!("http://localhost:{outside}/"),
        Some(&home.0),
        None
    ));
    // A recorded port narrows the set back to what the daemon actually uses.
    let recorded = guard_home("window-recorded", Some(51234));
    assert_eq!(
        guard_daemon_ports(Some(&recorded.0), None),
        vec![4781, 51234]
    );
}

fn artifact(tool: &str, page: Option<&str>) -> guard_contracts::BrowserMcpArtifactV1 {
    let mut metadata = serde_json::Map::new();
    metadata.insert("server_name".to_owned(), json!("playwright"));
    // Production artifacts carry the tool identity, which marks a plain `playwright` server as a
    // browser driver.
    metadata.insert("mcp_tool_identity".to_owned(), json!({"tool_name": tool}));
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
fn browser_calls_on_the_approval_center_carry_the_category() {
    let home = guard_home("risk", Some(51234));
    let categories = |tool: &str, page: Option<&str>, arguments: serde_json::Value| {
        with_guard_home(&home.0, || {
            evaluate_tool_risk(&artifact(tool, page), &arguments).unwrap()
        })
    };
    let guard_page = "http://localhost:51234/approvals/pending";
    let clicked = categories(
        "browser_click",
        Some(guard_page),
        json!({"element": "Approve", "ref": "e7"}),
    );
    assert!(
        clicked.iter().any(|name| name == "browser_guard_origin"),
        "{clicked:?}"
    );
    let opened = categories(
        "browser_navigate",
        None,
        json!({"url": "http://127.0.0.1:51234/"}),
    );
    assert!(
        opened.iter().any(|name| name == "browser_guard_origin"),
        "{opened:?}"
    );
    let elsewhere = categories(
        "browser_navigate",
        None,
        json!({"url": "https://example.com/"}),
    );
    assert!(
        !elsewhere.iter().any(|name| name == "browser_guard_origin"),
        "{elsewhere:?}"
    );
}

#[test]
fn the_reason_text_never_carries_the_approval_url() {
    let text = crate::mcp_tool_signals::guard_origin_signal_for_test();
    assert!(text.contains("approval center"), "{text}");
    assert!(!text.contains("http"), "{text}");
    assert!(!text.contains("4781"), "{text}");
}

#[test]
fn the_evidence_step_accepts_the_guard_origin_summary() {
    let input: guard_contracts::McpToolRiskInputV1 = serde_json::from_value(json!({
        "artifact": {"name": "playwright:browser_navigate", "command": "browser_navigate",
            "metadata": {"server_name": "playwright", "mcp_tool_identity": {"tool_name": "browser_navigate"}}},
        "arguments": {"format": "mapping", "entries": [["url", "http://localhost:51234/"]]},
        "risk_categories": ["browser_navigation", "browser_guard_origin"],
        "summary_code": "guard_origin",
    }))
    .unwrap();
    let evidence = crate::mcp_tool_signals::evaluate_risk_evidence(&input).unwrap();
    let summary = evidence["summary"].as_str().unwrap();
    assert!(summary.contains("approval center"), "{summary}");
    assert!(summary.contains("Ask the user"), "{summary}");
    // The stopped agent must not learn where the approval center is.
    for leak in [
        "51234",
        "://",
        "http",
        "localhost",
        "127.0.0.1",
        "[::1]",
        "/approvals",
    ] {
        assert!(!summary.contains(leak), "{leak} in {summary}");
    }
    let signals = evidence["signals"].to_string();
    assert!(signals.contains("Guard's own approval center"), "{signals}");
}
