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
fn a_literal_member_named_like_the_number_token_stays_a_member() {
    let token = ARBITRARY_PRECISION_TOKEN;
    let mut lone = Map::new();
    lone.insert(token.to_owned(), json!("1"));
    let value = parse_strict(format!(r#"{{"result":{{"{token}":"1"}}}}"#).as_bytes()).unwrap();
    assert_eq!(value["result"], Value::Object(lone));
    assert!(!value["result"].is_number());

    for body in [
        format!(r#"{{"result":{{"{token}":"1","verdict":"clean"}}}}"#),
        format!(r#"{{"result":{{"verdict":"clean","{token}":"1"}}}}"#),
    ] {
        let value = parse_strict(body.as_bytes()).unwrap();
        assert_eq!(value["result"]["verdict"], json!("clean"), "{body}");
        assert_eq!(value["result"][token], json!("1"), "{body}");
    }

    let escaped = r#"{"result":{"\u0024serde_json::private::Number":"7"}}"#;
    let value = parse_strict(escaped.as_bytes()).unwrap();
    assert_eq!(value["result"][token], json!("7"));

    for odd in [
        json!({"nested": 1}),
        json!([1]),
        json!(true),
        json!(null),
        json!(5),
    ] {
        let body = format!(r#"{{"result":{{"{token}":{odd}}}}}"#);
        let value = parse_strict(body.as_bytes()).unwrap();
        assert_eq!(value["result"][token], odd, "{body}");
    }

    let twice = format!(r#"{{"result":{{"{token}":"1","{token}":"2"}}}}"#);
    assert!(parse_strict(twice.as_bytes()).is_none());
    let big = parse_strict(br#"{"n":123456789012345678901234567890}"#).unwrap();
    assert!(big["n"].is_number());
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
