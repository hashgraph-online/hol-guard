//! The Muse answer of the native bounded bridge against a scripted daemon:
//! the document Muse reads, the approval a `PreToolUse` review waits for,
//! and the fail-closed envelope Muse reads on exit 0.

use std::io::BufReader;
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::json;

use super::*;
use crate::bounded_hook_bridge_render::failure_payload;
use crate::claude_hook_bridge_fixture::{read_request, write_private, write_response, GuardHome};

const TOKEN: &str = "bounded-muse-token-fixture";
const PRE_TOOL: &[u8] = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;
const REVIEW: &str =
    r#"{"policy_action":"review","reason":"held for review","approval_request_id":"req 1"}"#;

fn muse_home(label: &str, port: u16) -> GuardHome {
    let home = GuardHome::new(label);
    write_private(
        &home.state_path,
        &json!({"host": "127.0.0.1", "port": port}).to_string(),
    );
    write_private(&home.home.join(TOKEN_FILE), TOKEN);
    home
}

fn muse_config(home: &GuardHome) -> BridgeConfig {
    BridgeConfig {
        harness: "muse".to_owned(),
        guard_home: home.home.clone(),
        timeout: Duration::from_secs(20),
        start_command: Vec::new(),
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

/// Answer each request in turn with the next of `answers`, and return the
/// targets asked for.
fn serve(listener: TcpListener, answers: Vec<&'static str>) -> JoinHandle<Vec<String>> {
    std::thread::spawn(move || {
        let mut targets = Vec::new();
        for body in answers {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut writer = stream.try_clone().unwrap();
            let Some(request) = read_request(&mut BufReader::new(stream)) else {
                break;
            };
            assert_eq!(request.header("X-Guard-Token"), Some(TOKEN));
            targets.push(request.target);
            write_response(&mut writer, 200, body, true);
        }
        targets
    })
}

fn respond(stdout: &str, exit_code: i32) -> Route {
    Route::Respond {
        stdout: stdout.to_owned(),
        stderr: String::new(),
        exit_code,
    }
}

const DENY_DOCUMENT: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"held for review"}}"#;

#[test]
fn an_approved_muse_review_lets_the_call_through() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let daemon = serve(
        listener,
        vec![
            REVIEW,
            r#"{"request_id":"req 1","status":"pending"}"#,
            r#"{"request_id":"req 1","status":"resolved","resolution_action":"allow"}"#,
        ],
    );
    let home = muse_home("bounded-muse-allow", port);

    let route = route_hook(&muse_config(&home), PRE_TOOL, soon());

    // Muse reads an allow as empty stdout on exit 0.
    assert_eq!(route, respond("", 0));
    assert_eq!(
        daemon.join().unwrap(),
        [
            "/v1/hooks/muse",
            "/v1/requests/req%201",
            "/v1/requests/req%201"
        ]
    );
}

#[test]
fn a_denied_muse_review_stays_blocked() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let daemon = serve(
        listener,
        vec![
            REVIEW,
            r#"{"request_id":"req 1","status":"resolved","resolution_action":"deny"}"#,
        ],
    );
    let home = muse_home("bounded-muse-deny", port);

    let route = route_hook(&muse_config(&home), PRE_TOOL, soon());

    assert_eq!(route, respond(DENY_DOCUMENT, 0));
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn a_muse_review_left_pending_keeps_its_deny() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = muse_home("bounded-muse-pending", port);
    // The render reserve leaves a 4-second hook a 1-second wait.
    let config = BridgeConfig {
        timeout: Duration::from_secs(4),
        ..muse_config(&home)
    };
    let pending = r#"{"request_id":"req 1","status":"pending"}"#;
    let daemon = serve(listener, vec![REVIEW, pending]);

    let route = route_hook(&config, PRE_TOOL, Instant::now() + config.timeout);

    assert_eq!(route, respond(DENY_DOCUMENT, 0));
    // Later reads find no daemon, and the wait still ends with the hook.
    assert_eq!(daemon.join().unwrap().len(), 2);
}

#[test]
fn muse_answers_that_do_not_wait_render_as_muse_reads_them() {
    let cases: [(&[u8], &'static str, &str); 4] = [
        (
            PRE_TOOL,
            r#"{"policy_action":"block","reason":"blocked by policy"}"#,
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked by policy"}}"#,
        ),
        (PRE_TOOL, r#"{"policy_action":"allow"}"#, ""),
        (
            br#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#,
            r#"{"policy_action":"block","reason":"no é"}"#,
            r#"{"decision":"block","reason":"no \u00e9"}"#,
        ),
        (
            br#"{"hook_event_name":"SessionStart"}"#,
            r#"{"policy_action":"allow"}"#,
            r#"{"hookSpecificOutput":{"additionalContext":"HOL Guard protection is active for this workspace.","hookEventName":"SessionStart"}}"#,
        ),
    ];
    for (index, (hook, answer, stdout)) in cases.into_iter().enumerate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let daemon = serve(listener, vec![answer]);
        let home = muse_home(&format!("bounded-muse-render-{index}"), port);

        let route = route_hook(&muse_config(&home), hook, soon());

        assert_eq!(route, respond(stdout, 0), "{answer}");
        assert_eq!(daemon.join().unwrap(), ["/v1/hooks/muse"]);
    }
}

#[test]
fn a_muse_failure_travels_in_the_envelope_on_exit_zero() {
    let (payload, code) = failure_payload("muse", "PreToolUse", "reason");
    assert_eq!(code, 0);
    assert!(payload.get("hookSpecificOutput").is_some());
    assert_eq!(failure_payload("kimi", "PreToolUse", "reason").1, 2);
}
