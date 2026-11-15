use serde_json::json;

use super::*;

#[test]
fn answers_decode_to_values_and_raised_errors() {
    assert_eq!(decode(br#"{"ok":{"a":1}}"#), Ok(json!({"a": 1})));
    assert_eq!(decode(br#"{"ok":null}"#), Ok(Value::Null));
    let raised = decode(br#"{"error":{"kind":"not_found","type":"X","message":"m"}}"#);
    assert_eq!(
        raised.as_ref().err().and_then(CallError::kind),
        Some("not_found")
    );
    for answer in [&b""[..], b"[]", b"{}", b"{\"error\":1}", b"not json"] {
        assert_eq!(decode(answer), Err(CallError::NoAnswer));
    }
}

#[test]
fn worker_host_arguments_name_the_guard_home() {
    assert_eq!(
        host_args("/h"),
        ["desktop", "daemon-workers", "--guard-home", "/h"].map(str::to_owned)
    );
}

fn journaled(home: &std::path::Path) -> Vec<String> {
    let (events, _) = super::super::lifecycle::load_events(home, 64, false);
    events
        .iter()
        .filter_map(|event| {
            event
                .get("event")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

#[test]
fn worker_host_start_steps_are_journaled_before_ready() {
    let home = tempfile::tempdir().unwrap();
    let (sender, receiver) = mpsc::channel();
    let mut lines = &b"phase launched\nphase admitted\nready\nphase late\n"[..];
    read_host_start(&mut lines, home.path(), Some(sender));
    assert!(receiver.try_recv().is_ok());
    assert_eq!(journaled(home.path()), ["host_launched", "host_admitted"]);
}

#[test]
fn a_host_that_says_anything_else_is_not_ready() {
    let home = tempfile::tempdir().unwrap();
    for output in [
        &b"phase launched\nnot ready\nready\n"[..],
        b"phase launched\n",
        b"",
    ] {
        let (sender, receiver) = mpsc::channel();
        let mut lines = output;
        read_host_start(&mut lines, home.path(), Some(sender));
        assert!(receiver.try_recv().is_err());
    }
    let (sender, receiver) = mpsc::channel();
    let flood = "phase step\n".repeat(MAX_HOST_PHASES + 1) + "ready\n";
    read_host_start(&mut flood.as_bytes(), home.path(), Some(sender));
    assert!(receiver.try_recv().is_err());
}
