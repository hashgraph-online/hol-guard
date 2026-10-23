use super::*;
use serde_json::json;

#[test]
fn v2_orders_keys_by_utf16_code_units() {
    let value = json!({"\u{ffff}": 1, "\u{10000}": 2, "a": 3});
    let text = String::from_utf8(v2_canonical_bytes(&value).unwrap()).unwrap();
    assert_eq!(text, "{\"a\":3,\"\u{10000}\":2,\"\u{ffff}\":1}");
}

#[test]
fn v2_rejects_floats_and_checks_limits() {
    let float: Value = serde_json::from_str("1.5").unwrap();
    assert_eq!(v2_check(&float, 0), Err("unsupported_number"));
    assert!(v2_canonical_bytes(&float).is_err());
    let long_key = json!({ "k".repeat(129): 1 });
    assert_eq!(v2_check(&long_key, 0), Err("limit_key"));
}

#[test]
fn v1_limits_flag_depth_and_size() {
    let mut deep = json!(1);
    for _ in 0..42 {
        deep = json!([deep]);
    }
    assert_eq!(v1_resource_limit_error(&deep), Some("limit_depth"));
    assert_eq!(v1_resource_limit_error(&json!({"a": [1, "x"]})), None);
}

#[test]
fn stable_serialization_is_sorted_and_unescaped() {
    let value = json!({"b": "é\u{7f}", "a": [1, 2.5, null]});
    assert_eq!(
        stable_serialize(&value).unwrap(),
        "{\"a\":[1,2.5,null],\"b\":\"é\u{7f}\"}"
    );
}
