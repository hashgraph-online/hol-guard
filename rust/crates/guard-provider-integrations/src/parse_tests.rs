use serde_json::json;

use super::*;

#[test]
fn duplicate_keys_are_refused_at_every_depth() {
    assert!(parse_strict(br#"{"verdict":"ok","verdict":"bad"}"#).is_none());
    assert!(parse_strict(br#"{"result":{"score":1,"score":2}}"#).is_none());
    assert!(parse_strict(br#"{"items":[{"a":1,"a":1}]}"#).is_none());
    assert_eq!(
        parse_strict(br#"{"result":{"score":1.5,"tags":["a"]},"ok":true}"#),
        Some(json!({"result": {"score": 1.5, "tags": ["a"]}, "ok": true}))
    );
}

#[test]
fn trailing_bytes_and_oversize_bodies_are_refused() {
    assert!(parse_strict(br#"{"a":1} {"a":2}"#).is_none());
    assert!(parse_strict(b"").is_none());
    let mut big = b"\"".to_vec();
    big.resize(MAX_BODY_BYTES, b'a');
    big.push(b'"');
    assert!(parse_strict(&big).is_none());
}

#[test]
fn numbers_survive_arbitrary_precision() {
    let value = parse_strict(br#"{"n":12,"f":0.25,"neg":-3}"#).unwrap();
    assert_eq!(value["n"], json!(12));
    assert_eq!(value["f"], json!(0.25));
    assert_eq!(value["neg"], json!(-3));
}

#[test]
fn pointers_are_bounded() {
    assert!(is_bounded_pointer(""));
    assert!(is_bounded_pointer("/result/verdict"));
    assert!(is_bounded_pointer("/a~1b/c~0d"));
    assert!(!is_bounded_pointer("result"));
    assert!(!is_bounded_pointer("/a~2"));
    assert!(!is_bounded_pointer("/a~"));
    let deep = "/a".repeat(MAX_POINTER_SEGMENTS + 1);
    assert!(!is_bounded_pointer(&deep));
    assert!(is_bounded_pointer(&"/a".repeat(MAX_POINTER_SEGMENTS)));
}

#[test]
fn string_reads_refuse_long_and_wrong_typed_values() {
    let document = json!({
        "result": {"verdict": "malicious", "score": 9, "codes": ["phishing", 4, "x".repeat(80), "brand"]}
    });
    assert_eq!(
        read_string(&document, "/result/verdict", 32),
        Some("malicious")
    );
    assert_eq!(read_string(&document, "/result/verdict", 4), None);
    assert_eq!(read_string(&document, "/result/score", 32), None);
    assert_eq!(read_string(&document, "/result/missing", 32), None);
    assert_eq!(read_string(&document, "result/verdict", 32), None);
    assert_eq!(
        read_strings(&document, "/result/codes", 8, 32),
        Some(vec!["phishing", "brand"])
    );
    assert_eq!(
        read_strings(&document, "/result/codes", 1, 32),
        Some(vec!["phishing"])
    );
    assert_eq!(read_strings(&document, "/result/verdict", 8, 32), None);
}
