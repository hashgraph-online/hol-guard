use serde_json::{json, Map, Value};

use super::remote_scan;

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => unreachable!("test requests are objects"),
    }
}

fn scan(harnesses: Value, remote_count: usize) -> Value {
    remote_scan(&object(json!({
        "op": "remote_scan",
        "harnesses": harnesses,
        "remote_count": remote_count,
        "limit": 100,
    })))
    .expect("answer")["harnesses"]
        .clone()
}

#[test]
fn a_full_read_covers_each_detected_harness_once_in_order() {
    assert_eq!(
        scan(json!(["cursor", "codex", "cursor", "claude-code"]), 3),
        json!(["claude-code", "codex", "cursor"])
    );
    assert_eq!(scan(json!([]), 0), json!([]));
}

#[test]
fn a_remote_list_at_its_cap_covers_no_harness() {
    assert_eq!(scan(json!(["codex"]), 100), Value::Null);
    assert_eq!(scan(json!(["codex"]), 101), Value::Null);
    assert_eq!(scan(json!(["codex"]), 99), json!(["codex"]));
}

#[test]
fn a_malformed_scan_request_is_refused() {
    for request in [
        json!({"op": "remote_scan", "remote_count": 1, "limit": 100}),
        json!({"op": "remote_scan", "harnesses": {}, "remote_count": 1, "limit": 100}),
        json!({"op": "remote_scan", "harnesses": [1], "remote_count": 1, "limit": 100}),
        json!({"op": "remote_scan", "harnesses": [], "remote_count": -1, "limit": 100}),
        json!({"op": "remote_scan", "harnesses": [], "remote_count": "1", "limit": 100}),
        json!({"op": "remote_scan", "harnesses": [], "remote_count": 1, "limit": null}),
        json!({"op": "remote_scan", "harnesses": [], "remote_count": 1, "limit": 100, "extra": 1}),
    ] {
        assert!(remote_scan(&object(request)).is_err());
    }
}
