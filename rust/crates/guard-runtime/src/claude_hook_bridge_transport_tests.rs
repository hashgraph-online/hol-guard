//! Failure classification, `repr` and event-name reads of the transport.

use super::*;

fn http(status: u16, detail: &str) -> BridgeError {
    BridgeError::Http {
        status,
        detail: detail.to_owned(),
    }
}

#[test]
fn failures_are_classified_as_python_does() {
    let cases = [
        (http(401, ""), "authenticated-control-plane-failure", false),
        (
            http(403, "no"),
            "authenticated-control-plane-failure",
            false,
        ),
        (http(429, ""), "overload", false),
        (http(503, "Server Busy"), "overload", false),
        (http(503, "down"), "transport-failure", true),
        (http(404, ""), "transport-failure", false),
        (
            BridgeError::Value("bad".into()),
            "authenticated-control-plane-failure",
            false,
        ),
        (
            BridgeError::Transport("timed out".into()),
            "transport-failure",
            true,
        ),
    ];
    for (error, kind, recoverable) in cases {
        assert_eq!(error.failure_kind(), kind, "{error:?}");
        assert_eq!(error.is_recoverable(), recoverable, "{error:?}");
    }
    assert_eq!(http(503, "down").reason(), "daemon returned HTTP 503: down");
    assert_eq!(http(503, "").reason(), "daemon returned HTTP 503");
    assert_eq!(
        BridgeError::Transport("timed out".into()).reason(),
        "timed out"
    );
}

#[test]
fn repr_matches_cpython() {
    assert_eq!(py_repr("https"), "'https'");
    assert_eq!(py_repr("it's"), "\"it's\"");
    assert_eq!(py_repr("both ' \""), "'both \\' \"'");
    assert_eq!(py_repr("a\tb\n\u{1}\u{7f}\\"), "'a\\tb\\n\\x01\\x7f\\\\'");
    assert_eq!(py_repr("\u{e9}\u{a0}\u{200b}"), "'\u{e9}\\xa0\\u200b'");
    assert_eq!(py_repr("\u{10ffff}"), "'\\U0010ffff'");
}

#[test]
fn event_name_prefers_hook_event_name() {
    let cases = [
        (
            r#"{"hook_event_name":" Stop ","event":"PreToolUse"}"#,
            "Stop",
        ),
        (r#"{"event":"PostToolUse"}"#, "PostToolUse"),
        (
            r#"{"hook_event_name":7,"event":"PostToolUse"}"#,
            "PreToolUse",
        ),
        (r#"{"hook_event_name":"  "}"#, "PreToolUse"),
        ("not json", "PreToolUse"),
        ("[1]", "PreToolUse"),
    ];
    for (data, name) in cases {
        assert_eq!(hook_event_name(data), Ok(name.to_owned()), "{data}");
    }
}
