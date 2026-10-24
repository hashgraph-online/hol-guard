//! Replay recorded MCP launch decisions through the Rust gate.
//!
//! `mcp_launch_tokens` decides whether pasted text is one safe invocation Guard
//! may launch as an MCP server. The CLI route reaches that decision through
//! Python's `local_mcp_probe.mcp_launch_tokens` and the resident route reaches
//! it through this one, so the two are separate implementations of a single
//! security predicate. Every case here was recorded from the Python half, which
//! means an accepted case is text Python would launch and a refusal is text
//! Python refuses.
//!
//! This runs wherever the module is compiled. The crate's own unit tests for
//! the same file are `#[cfg(all(unix, test))]`, so before this file nothing
//! exercised the gate on Windows.

#![cfg(any(unix, windows))]

use guard_command::local_mcp_stdio::mcp_launch_tokens;
use serde_json::Value;
use std::path::Path;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/mcp-launch-tokens.v1.json");

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case is missing {field}"))
}

/// The tokens the fixture recorded, or `None` for a refusal.
fn expected(case: &Value) -> Option<Vec<String>> {
    match case.get("tokens") {
        Some(Value::Null) | None => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .unwrap_or_else(|| panic!("a recorded token is not a string"))
                        .to_owned()
                })
                .collect(),
        ),
        Some(other) => panic!("tokens must be a list or null, got {other}"),
    }
}

#[test]
fn recorded_launch_decisions_replay() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-mcp-launch-tokens-parity.v1",
        "fixture schema moved"
    );
    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "fixture records no cases");

    // One empty directory for both roles, so no case can depend on what is on disk.
    let root = tempfile::tempdir().expect("temporary directory");
    let cwd: &Path = root.path();

    let mut accepted = 0usize;
    let mut refused = 0usize;
    for case in cases {
        let name = text(case, "name");
        let decided = mcp_launch_tokens(text(case, "command_text"), cwd, Some(cwd));
        assert_eq!(decided, expected(case), "case {name} disagrees with Python");
        if expected(case).is_some() {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    assert!(
        accepted >= 8,
        "the fixture must keep recording text that launches"
    );
    assert!(
        refused >= 8,
        "the fixture must keep recording text that is refused"
    );
}
