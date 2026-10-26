//! The browser approval wait: Python parity for the pending-request lookup,
//! the resolution table, and the poll and live-decision exchange against a
//! scripted daemon.

use std::time::{Duration, Instant};

use serde_json::Value;

use super::super::tests::{codex_home, TOKEN};
use super::*;
use crate::claude_hook_bridge_fixture::Exchange;
use crate::pyjson::parse_mapping_lone_surrogates;

/// Daemon answers with what `pending_pretool_approval` returned for each in
/// Python (`python`) and what the bridge waits on (`native`: `null` where
/// Python's id holds a character no daemon request id contains).
const VECTORS: &str = include_str!("../testdata/codex_hook_bridge/pending_approval.json");
const HOOK_INPUT: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;

fn parsed(text: &str) -> PyVal {
    parse_mapping_lone_surrogates(text).unwrap().value
}

fn expected(value: &Value) -> Option<Pending> {
    let pair = value.as_array()?;
    Some(Pending {
        request_id: pair[0].as_str().unwrap().to_owned(),
        approval_url: pair[1].as_str().map(str::to_owned),
    })
}

#[test]
fn pending_requests_match_python() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(!vectors.is_empty());
    for vector in &vectors {
        let response = parsed(vector["response"].as_str().unwrap());
        assert_eq!(
            pending_pretool_approval(&response, PRE_TOOL_USE),
            expected(&vector["native"]),
            "{vector}"
        );
        if vector["python"].is_null() {
            assert!(vector["native"].is_null(), "{vector}");
        }
        assert_eq!(
            pending_pretool_approval(&response, "PermissionRequest"),
            None,
            "{vector}"
        );
    }
}

#[test]
fn resolutions_map_as_python_maps_them() {
    for (payload, action) in [
        (
            r#"{"status":"resolved","resolution_action":"allow","policy_action":"review"}"#,
            Some(Action::Allow),
        ),
        (
            r#"{"status":"resolved","resolution_action":"allow","policy_action":"require-reapproval"}"#,
            Some(Action::Allow),
        ),
        // An allow of anything but a reviewed request stays blocked.
        (
            r#"{"status":"resolved","resolution_action":"allow","policy_action":"block"}"#,
            Some(Action::Block),
        ),
        (
            r#"{"status":"resolved","resolution_action":"allow"}"#,
            Some(Action::Block),
        ),
        (
            r#"{"status":"resolved","resolution_action":"denied"}"#,
            Some(Action::Block),
        ),
        (
            r#"{"status":"resolved","resolution_action":"blocked"}"#,
            Some(Action::Block),
        ),
        (
            r#"{"status":"resolved","resolution_action":"Allow","policy_action":"review"}"#,
            None,
        ),
        (
            r#"{"status":"pending","resolution_action":"allow","policy_action":"review"}"#,
            None,
        ),
        (r#"{"status":"resolved","resolution_action":1}"#, None),
        (r#"{"status":"resolved"}"#, None),
    ] {
        assert_eq!(resolution_action(&parsed(payload)), action, "{payload}");
    }
}

#[test]
fn the_allow_is_rendered_as_python_renders_it() {
    assert_eq!(
        allow_rendered(),
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}"#
    );
}

fn pending() -> Pending {
    Pending {
        request_id: "req_12345678".to_owned(),
        approval_url: None,
    }
}

const RESOLVED_ALLOW: &str =
    r#"{"status":"resolved","resolution_action":"allow","policy_action":"review"}"#;

#[test]
fn a_browser_allow_recorded_by_the_daemon_is_approved() {
    let (home, daemon) = codex_home(
        "codex-approval-allow",
        vec![
            Exchange::Plain(404, "{}".to_owned()),
            Exchange::Plain(200, r#"{"status":"pending"}"#.to_owned()),
            Exchange::Plain(200, RESOLVED_ALLOW.to_owned()),
            Exchange::Plain(200, r#"{"completed":true,"action":"allow"}"#.to_owned()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(approved(&home.state_path, &pending(), HOOK_INPUT, deadline));
    let requests = daemon.join().unwrap();
    let targets: Vec<&str> = requests.iter().map(|r| r.target.as_str()).collect();
    assert_eq!(
        targets,
        [
            "/v1/requests/req_12345678",
            "/v1/requests/req_12345678",
            "/v1/requests/req_12345678",
            "/v1/requests/req_12345678/live-decision",
        ]
    );
    for request in &requests {
        assert_eq!(request.header("X-Guard-Token"), Some(TOKEN));
    }
    assert!(requests[0].body.is_empty());
    let body: Value = serde_json::from_slice(&requests[3].body).unwrap();
    assert_eq!(body["hook_input"], Value::String(HOOK_INPUT.to_owned()));
    assert_eq!(requests[3].header("Content-Type"), Some("application/json"));
}

#[test]
fn a_browser_block_keeps_the_deny() {
    let (home, daemon) = codex_home(
        "codex-approval-block",
        vec![
            Exchange::Plain(
                200,
                r#"{"status":"resolved","resolution_action":"block"}"#.to_owned(),
            ),
            Exchange::Plain(200, r#"{"completed":true,"action":"block"}"#.to_owned()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(!approved(
        &home.state_path,
        &pending(),
        HOOK_INPUT,
        deadline
    ));
    let requests = daemon.join().unwrap();
    assert_eq!(
        requests[1].target,
        "/v1/requests/req_12345678/live-decision"
    );
}

#[test]
fn an_allow_the_daemon_does_not_record_keeps_the_deny() {
    for completion in [
        Exchange::Plain(200, r#"{"completed":false,"action":"allow"}"#.to_owned()),
        Exchange::Plain(200, r#"{"completed":true,"action":"block"}"#.to_owned()),
        Exchange::Plain(200, r#"{"completed":1,"action":"allow"}"#.to_owned()),
        Exchange::Plain(409, r#"{"completed":true,"action":"allow"}"#.to_owned()),
        Exchange::Plain(200, "[]".to_owned()),
    ] {
        let (home, daemon) = codex_home(
            "codex-approval-unrecorded",
            vec![
                Exchange::Plain(200, RESOLVED_ALLOW.to_owned()),
                completion.clone(),
            ],
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        assert!(
            !approved(&home.state_path, &pending(), HOOK_INPUT, deadline),
            "{completion:?}"
        );
        assert_eq!(daemon.join().unwrap().len(), 2);
    }
}

#[test]
fn an_unresolved_request_keeps_the_deny_at_the_deadline() {
    // The scripted daemon outlasts the wait; its thread is left behind.
    let (home, _daemon) = codex_home(
        "codex-approval-timeout",
        vec![Exchange::Plain(404, "{}".to_owned()); 64],
    );
    let started = Instant::now();
    let deadline = started + Duration::from_millis(900);
    assert!(!approved(
        &home.state_path,
        &pending(),
        HOOK_INPUT,
        deadline
    ));
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(600), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
}
