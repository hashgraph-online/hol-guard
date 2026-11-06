use super::*;
use serde_json::json;

#[test]
fn response_key_canonicalizes_sort_order() {
    // `{"a":1,"b":2}` id must correlate regardless of source key order.
    let a = json!({"a":1,"b":2});
    let b = json!({"b":2,"a":1});
    assert_eq!(response_key(Some(&a)), response_key(Some(&b)));
    assert_eq!(response_key(Some(&a)).unwrap(), "{\"a\":1,\"b\":2}");
    assert_eq!(response_key(Some(&json!(7))).unwrap(), "7");
    assert_eq!(response_key(Some(&json!("x"))).unwrap(), "\"x\"");
    assert_eq!(response_key(Some(&Value::Null)), Some("null".into()));
    assert_eq!(response_key(None), None);
}

#[test]
fn frame_classification() {
    assert!(is_request(&json!({"method":"tools/call","id":1})));
    assert!(!is_request(&json!({"id":1,"result":{}})));
    assert!(is_response(&json!({"id":1,"result":{}})));
    assert!(!is_response(&json!({"method":"tools/call","id":1})));
    assert!(is_notification(
        &json!({"method":"notifications/cancelled"})
    ));
    assert!(!is_notification(&json!({"id":1})));
}

#[test]
fn buffered_response_fifo_and_key() {
    let mut buf = ResponseBuffers::default();
    let r1 = json!({"id":1,"result":{"a":1}});
    let r2 = json!({"id":1,"result":{"a":2}});
    buf.buffer(r1.clone());
    buf.buffer(r2.clone());
    // FIFO within a correlation key.
    assert_eq!(buf.pop(&json!(1)), Some(r1));
    assert_eq!(buf.pop(&json!(1)), Some(r2));
    assert_eq!(buf.pop(&json!(1)), None);
    // An id-less message carries no correlation key and buffers nothing.
    buf.buffer(json!({"result":{}}));
    assert_eq!(buf.pop(&json!(2)), None);
    // Per-key isolation.
    buf.buffer(json!({"id":9,"result":{}}));
    assert_eq!(buf.pop(&json!(3)), None);
    assert_eq!(buf.pop(&json!(9)), Some(json!({"id":9,"result":{}})));
}
