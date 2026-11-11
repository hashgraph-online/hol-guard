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
