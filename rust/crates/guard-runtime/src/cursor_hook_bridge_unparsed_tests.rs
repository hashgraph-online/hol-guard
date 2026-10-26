//! The Cursor bridge's own answer to a hook its client cannot parse:
//! `_exit_unparseable_cursor_input`, printed without Python or the daemon.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use serde_json::json;

use super::*;
use crate::claude_hook_bridge_fixture::{write_private, GuardHome};
use crate::cursor_hook_bridge_response::UNAVAILABLE_STDOUT;

/// `print(json.dumps(response))` for `cursor_unparseable_input_permission`.
const DENIED: &str = "{\"permission\": \"deny\", \"user_message\": \"Guard could not process this hook request safely. Retry or repair Guard from a terminal.\"}\n";
/// `print(json.dumps(response))` for `_cursor_unavailable_response`.
const UNAVAILABLE: &str = "{\"permission\": \"deny\", \"user_message\": \"HOL Guard could not complete the native hook decision safely.\"}\n";
const OBSERVED: &str = "{}\n";

/// A Guard home whose daemon listens, unanswered, on `listener`.
fn listening_home(label: &str, listener: &TcpListener) -> GuardHome {
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = GuardHome::new(&format!("cursor-unparsed-{label}"));
    write_private(
        &home.state_path,
        &json!({"host": "127.0.0.1", "port": port}).to_string(),
    );
    write_private(
        &home.home.join("daemon-auth-token"),
        "cursor-unparsed-token",
    );
    home
}

fn client_named(home: &GuardHome, event: &str, deadline: Instant) -> Client {
    Client {
        guard_home: home.home_text().to_owned(),
        home: Some("/h".to_owned()),
        recovery_command: Vec::new(),
        event: event.to_owned(),
        deadline,
    }
}

fn assert_not_asked(listener: &TcpListener) {
    let refused = listener.accept().map(|_| ()).unwrap_err();
    assert_eq!(
        refused.kind(),
        ErrorKind::WouldBlock,
        "the daemon was asked"
    );
}

/// Hooks `_main_inner` hands to `_exit_unparseable_cursor_input`.
fn unparseable_inputs() -> Vec<Vec<u8>> {
    let mut oversized = br#"{"hook_event_name":"beforeShellExecution","command":"ls"}"#.to_vec();
    oversized.resize(MAX_HOOK_INPUT_BYTES + 1, b' ');
    let inputs: [&[u8]; 14] = [
        b"",
        b" \n\t\r",
        // `decode("utf-8-sig")` drops the mark, leaving a blank hook.
        b"\xef\xbb\xbf",
        // `json.loads` refuses a second mark.
        b"\xef\xbb\xbf\xef\xbb\xbf{}",
        b"\xff",
        b"{\"command\": \"\xed\xa0\x80\"}",
        b"{",
        b"{} {}",
        b"\xc2\xa0{}",
        b"{'command': 'ls'}",
        b"[]",
        b"null",
        b"\"preToolUse\"",
        b"7",
    ];
    inputs
        .iter()
        .map(|raw| raw.to_vec())
        .chain([oversized])
        .collect()
}

#[test]
fn unparseable_hooks_get_the_clients_answer_without_the_daemon() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let home = listening_home("answered", &listener);
    // The client names the hook from its argv, never from the input.
    let cases = [
        ("preToolUse", DENIED, 2),
        (" beforeReadFile ", DENIED, 2),
        ("beforeShellExecution", DENIED, 2),
        ("", DENIED, 2),
        ("afterShellExecution", OBSERVED, 0),
        (" After_MCP-Execution ", OBSERVED, 0),
    ];
    for (event, stdout, code) in cases {
        let client = client_named(&home, event, Instant::now() + Duration::from_secs(20));
        for raw in unparseable_inputs() {
            let shown = String::from_utf8_lossy(&raw[..raw.len().min(32)]).into_owned();
            assert_eq!(
                reply(&client, &raw),
                Reply::Answered(stdout.to_owned(), code),
                "{event:?} {shown:?}"
            );
        }
    }
    assert_not_asked(&listener);
}

#[test]
fn an_unparseable_hook_past_its_deadline_is_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let home = listening_home("late", &listener);
    for (event, stdout, code) in [
        ("preToolUse", UNAVAILABLE, 2),
        ("", UNAVAILABLE, 2),
        ("aftershellexecution", OBSERVED, 0),
    ] {
        let client = client_named(&home, event, Instant::now());
        assert_eq!(
            reply(&client, b"{"),
            Reply::Answered(stdout.to_owned(), code),
            "{event:?}"
        );
    }
    assert_not_asked(&listener);
}

#[test]
fn json_the_port_cannot_represent_fails_closed_without_the_daemon() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let home = listening_home("kept", &listener);
    let deadline = Instant::now() + Duration::from_secs(20);
    let denied = Reply::Answered(UNAVAILABLE_STDOUT.to_owned(), 2);
    let observed = Reply::Answered(AFTER_STDOUT.to_owned(), 0);
    let tool = client_named(&home, "preToolUse", deadline);
    let observer = client_named(&home, "afterShellExecution", deadline);
    for (client, raw, expected) in [
        (&tool, &br#"{"command": NaN}"#[..], &denied),
        (&tool, &br#"{"command": -Infinity}"#[..], &denied),
        (&tool, &br#"{"hook_event_name":"stop"}"#[..], &denied),
        // An observer the client was not installed as is still denied.
        (
            &tool,
            &br#"{"hook_event_name":"afterShellExecution","command": NaN}"#[..],
            &denied,
        ),
        (&observer, &br#"{"command": NaN}"#[..], &observed),
        (&observer, &br#"{"hook_event_name":"stop"}"#[..], &denied),
    ] {
        assert_eq!(
            &reply(client, raw),
            expected,
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
    assert_not_asked(&listener);
    // An observer named in another spelling is still observed, whether or
    // not it reaches the daemon.
    let raw = br#"{"hook_event_name":"after_shell_execution","command":"ls"}"#;
    assert_eq!(reply(&observer, raw), observed);
}
