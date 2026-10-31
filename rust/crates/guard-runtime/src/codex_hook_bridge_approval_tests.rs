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

#[test]
fn a_lost_completion_is_replayed_for_the_same_hook() {
    let (home, daemon) = codex_home(
        "codex-approval-lost-completion",
        vec![
            Exchange::Plain(200, RESOLVED_ALLOW.to_owned()),
            Exchange::Drop,
            Exchange::Plain(200, r#"{"completed":true,"action":"allow"}"#.to_owned()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(approved(&home.state_path, &pending(), HOOK_INPUT, deadline));
    let requests = daemon.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[1].target,
        "/v1/requests/req_12345678/live-decision"
    );
    assert_eq!(requests[1].target, requests[2].target);
    assert_eq!(requests[1].body, requests[2].body);
}

#[test]
fn completion_stops_after_three_lost_replies() {
    // A fourth attempt would be answered with a recorded allow; the deny
    // stands because the bridge never sends it. The test then takes that
    // connection itself so the daemon thread finishes and can be joined.
    let (home, daemon) = codex_home(
        "codex-approval-lost-every-completion",
        vec![
            Exchange::Plain(200, RESOLVED_ALLOW.to_owned()),
            Exchange::Drop,
            Exchange::Drop,
            Exchange::Drop,
            Exchange::Plain(200, r#"{"completed":true,"action":"allow"}"#.to_owned()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(!approved(
        &home.state_path,
        &pending(),
        HOOK_INPUT,
        deadline
    ));
    let state: Value = serde_json::from_slice(&std::fs::read(&home.state_path).unwrap()).unwrap();
    let port = state["port"].as_u64().unwrap();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port as u16)).unwrap();
    std::io::Write::write_all(
        &mut stream,
        b"GET /never-sent HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    std::io::Read::read_to_end(&mut stream, &mut Vec::new()).unwrap();
    let requests = daemon.join().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[4].target, "/never-sent");
}

#[test]
fn a_lost_poll_reply_is_asked_again() {
    let (home, daemon) = codex_home(
        "codex-approval-lost-poll",
        vec![
            Exchange::Drop,
            Exchange::Plain(200, RESOLVED_ALLOW.to_owned()),
            Exchange::Plain(200, r#"{"completed":true,"action":"allow"}"#.to_owned()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(approved(&home.state_path, &pending(), HOOK_INPUT, deadline));
    let requests = daemon.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].target, requests[1].target);
}

#[test]
fn a_refused_completion_is_not_replayed() {
    let (home, daemon) = codex_home(
        "codex-approval-refused-completion",
        vec![
            Exchange::Plain(200, RESOLVED_ALLOW.to_owned()),
            Exchange::Plain(401, r#"{"error":"unauthorized"}"#.to_owned()),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert!(!approved(
        &home.state_path,
        &pending(),
        HOOK_INPUT,
        deadline
    ));
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn a_rejected_completion_reports_the_daemon_code_once() {
    let (home, daemon) = codex_home(
        "codex-approval-rejected-completion",
        vec![Exchange::Plain(
            409,
            r#"{"completed":false,"error":"fresh_policy_revalidation_failed"}"#.to_owned(),
        )],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    assert_eq!(
        complete_resolution(
            &home.state_path,
            "req_12345678",
            Action::Allow,
            HOOK_INPUT,
            deadline
        ),
        Err("fresh_policy_revalidation_failed".to_owned())
    );
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn a_rejection_without_a_stable_code_is_not_repeated() {
    let long = "a".repeat(81);
    for body in [
        r#"{"completed":false,"error":"Policy Changed"}"#.to_owned(),
        r#"{"completed":false,"error":""}"#.to_owned(),
        format!(r#"{{"completed":false,"error":"{long}"}}"#),
        r#"{"completed":false,"error":1}"#.to_owned(),
        r#"{"completed":false}"#.to_owned(),
        "[]".to_owned(),
    ] {
        let (home, daemon) = codex_home(
            "codex-approval-rejected-unstable",
            vec![Exchange::Plain(409, body.clone())],
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        assert_eq!(
            complete_resolution(
                &home.state_path,
                "req_12345678",
                Action::Allow,
                HOOK_INPUT,
                deadline
            ),
            Ok(None),
            "{body}"
        );
        assert_eq!(daemon.join().unwrap().len(), 1);
    }
}

#[test]
fn the_rejection_notice_ends_with_the_stable_marker_line() {
    let notice = rejected_allow_notice("exact_approval_authority_missing");
    let lines: Vec<&str> = notice.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("HOL Guard kept this action blocked:"));
    assert!(lines[0].contains("(exact_approval_authority_missing)"));
    assert_eq!(
        lines[1],
        "guard_live_decision_rejection exact_approval_authority_missing"
    );
}

/// A writer whose every write fails, as a closed or broken stderr does.
struct BrokenStderr;

impl std::io::Write for BrokenStderr {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn a_broken_stderr_does_not_stop_a_notice_caller() {
    let notice = rejected_allow_notice("fresh_policy_revalidation_failed");
    notify(&mut BrokenStderr, &notice);
    let mut written = Vec::new();
    notify(&mut written, &notice);
    assert_eq!(String::from_utf8(written).unwrap(), format!("{notice}\n"));
}
