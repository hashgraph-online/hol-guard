//! Canonical form and error result shape.

use super::activation::{evaluator_trusting, payload, run_with_activation, sign, signer};
use super::*;

// ---- canonical form ----

#[test]
fn object_keys_sort_by_utf16_code_units_not_code_points() {
    // U+FF5E is one UTF-16 unit (0xFF5E); U+10000 is the surrogate pair
    // 0xD800 0xDC00. By code point U+FF5E sorts first; by UTF-16 it sorts last.
    let value: Value =
        serde_json::from_str("{\"\u{FF5E}\":1,\"\u{10000}\":2,\"a\":3,\"B\":4}").unwrap();
    let expected = "{\"B\":4,\"a\":3,\"\u{10000}\":2,\"\u{FF5E}\":1}";
    assert_eq!(
        String::from_utf8(canonical_bytes(&value).unwrap()).unwrap(),
        expected
    );
    let reversed: Value =
        serde_json::from_str("{\"B\":4,\"a\":3,\"\u{10000}\":2,\"\u{FF5E}\":1}").unwrap();
    assert_eq!(
        canonical_bytes(&reversed).unwrap(),
        canonical_bytes(&value).unwrap()
    );
    let nested: Value = serde_json::from_str("{\"o\":{\"\u{FF5E}\":1,\"\u{10000}\":2}}").unwrap();
    assert_eq!(
        String::from_utf8(canonical_bytes(&nested).unwrap()).unwrap(),
        "{\"o\":{\"\u{10000}\":2,\"\u{FF5E}\":1}}"
    );
}

#[test]
fn the_same_arguments_in_any_key_order_have_one_identity() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let forward = line_with_raw_arguments(
        &base,
        "{\"channel\":\"C0SYNTH01\",\"\u{FF5E}\":1,\"\u{10000}\":2}",
    );
    let backward = line_with_raw_arguments(
        &base,
        "{\"\u{10000}\":2,\"\u{FF5E}\":1,\"channel\":\"C0SYNTH01\"}",
    );
    let forward = evaluator.evaluate(forward.as_bytes());
    let backward = evaluator.evaluate(backward.as_bytes());
    assert_success(&forward);
    assert_eq!(
        forward["action_identity_sha256"],
        backward["action_identity_sha256"]
    );
}

#[test]
fn canonical_strings_use_minimal_escapes_and_no_normalization() {
    let value = Value::String("a\"b\\c\u{1}\u{8}\u{c}\n\r\t/\u{7f}\u{2028}\u{e9}".into());
    assert_eq!(
        String::from_utf8(canonical_bytes(&value).unwrap()).unwrap(),
        "\"a\\\"b\\\\c\\u0001\\b\\f\\n\\r\\t/\u{7f}\u{2028}\u{e9}\""
    );
    // Visually identical spellings are different actions.
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let composed =
        line_with_raw_arguments(&base, "{\"channel\":\"C0SYNTH01\",\"text\":\"caf\u{e9}\"}");
    let decomposed = line_with_raw_arguments(
        &base,
        "{\"channel\":\"C0SYNTH01\",\"text\":\"cafe\u{301}\"}",
    );
    let composed = evaluator.evaluate(composed.as_bytes());
    let decomposed = evaluator.evaluate(decomposed.as_bytes());
    assert_ne!(
        composed["action_identity_sha256"],
        decomposed["action_identity_sha256"]
    );
}

#[test]
fn canonical_arguments_reject_non_objects_and_domain_digests_are_separated() {
    assert_eq!(
        canonical_arguments(&json!([])),
        Err(CanonicalError::Malformed)
    );
    assert_eq!(
        canonical_arguments(&json!({"a": [true, null, 1]})).unwrap(),
        b"{\"a\":[true,null,1]}"
    );
    assert_ne!(
        domain_digest("one", &[b"ab"]),
        domain_digest("two", &[b"ab"])
    );
    // Length prefixes keep the part boundaries from sliding.
    assert_ne!(
        domain_digest("d", &[b"ab", b"c"]),
        domain_digest("d", &[b"a", b"bc"])
    );
}

// ---- error shape ----

#[test]
fn every_error_result_blocks_and_never_permits_dispatch() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let signer = signer();
    let mut cases: Vec<(String, &str)> = vec![
        ("{".into(), "malformed"),
        (
            line_with_raw_arguments(&base, r#"{"a":1,"a":2}"#),
            "duplicate_key",
        ),
        (
            line_with_raw_arguments(&base, &format!("{}1{}", "[".repeat(40), "]".repeat(40))),
            "too_deep",
        ),
        (
            line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","n":1.5}"#),
            "unsupported_number",
        ),
        (
            line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","n":9007199254740992}"#),
            "unsupported_number",
        ),
    ];
    let mutations: [(Edit, &str); 8] = [
        (
            |r| r["action"]["arguments"]["text"] = "a".repeat(70_000).into(),
            "too_large",
        ),
        (|r| r["extra"] = 1.into(), "invalid_request"),
        (
            |r| r["schema"] = "guard.cloud-action-evaluation.v2".into(),
            "unsupported_version",
        ),
        (
            |r| r["binding_set_digest"] = "0".repeat(64).into(),
            "binding_unavailable",
        ),
        (
            |r| r["action"]["action_id"] = "slack.unknown.thing".into(),
            "action_unknown",
        ),
        (
            |r| r["connection"]["provider"] = "example".into(),
            "connection_mismatch",
        ),
        (
            |r| r["activation"] = json!({"payload": {}, "signature": "AAAA"}),
            "activation_key_unavailable",
        ),
        (
            |r| {
                r["policy"]["rules"] = json!([{"rule_id": "r", "action": "allow", "match": {"action_id": "*", "x": 1}}])
            },
            "invalid_request",
        ),
    ];
    for (mutate, code) in mutations {
        let mut request = base.clone();
        mutate(&mut request);
        cases.push((request.to_string(), code));
    }
    cases.push((
        {
            let mut request = base.clone();
            request["activation"] = sign(&signer, &payload("ws-synthetic-1"));
            request.to_string()
        },
        "activation_key_unavailable",
    ));
    for (line, code) in cases {
        assert_error(&evaluator.evaluate(line.as_bytes()), code);
    }
    let limit = error_result(None, "limit");
    assert_error(&limit, "limit");
    assert_eq!(limit["request_id"], Value::Null);
}

#[test]
fn errors_found_after_parsing_echo_the_request_id_and_parse_errors_do_not() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["action"]["action_id"] = "slack.unknown.thing".into();
    assert_eq!(run(&evaluator, &request)["request_id"], "req-0001");
    let duplicate = line_with_raw_arguments(&request_for(&evaluator), r#"{"a":1,"a":2}"#);
    assert_eq!(
        evaluator.evaluate(duplicate.as_bytes())["request_id"],
        Value::Null
    );
}

#[test]
fn strings_serde_json_treats_as_internal_tokens_are_rejected_not_reinterpreted() {
    let escaped_prefix = "\\u0024serde_json::private::Number";
    for spelling in [
        r#"{"$serde_json::private::Number":"1"}"#.to_string(),
        r#"{"$serde_json::private::RawValue":"{\"a\":1,\"a\":2}"}"#.to_string(),
        format!("{{\"{escaped_prefix}\":\"1\"}}"),
        r#"{"k":"$serde_json::private::Number"}"#.to_string(),
        r#"["$serde_json::private::anything"]"#.to_string(),
    ] {
        let document = format!("{{\"x\":{spelling}}}");
        assert_eq!(
            parse_strict(document.as_bytes()),
            Err(CanonicalError::Malformed),
            "{document}"
        );
    }
    // Ordinary strings that merely resemble the prefix are untouched.
    let fine = r#"{"a":"$serde_json::private","b":"serde_json::private::Number","c":"\"$serde_json::private::\""}"#;
    assert!(parse_strict(fine.as_bytes()).is_ok());

    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let smuggled = line_with_raw_arguments(
        &base,
        r#"{"channel":"C0SYNTH01","x":{"$serde_json::private::RawValue":"{\"a\":1,\"a\":2}"}}"#,
    );
    assert_error(&evaluator.evaluate(smuggled.as_bytes()), "malformed");
    let number = line_with_raw_arguments(
        &base,
        r#"{"channel":"C0SYNTH01","x":{"$serde_json::private::Number":"1"}}"#,
    );
    assert_error(&evaluator.evaluate(number.as_bytes()), "malformed");
}

#[test]
fn a_reserved_token_spelled_entirely_in_escapes_is_still_rejected() {
    let token = "$serde_json::private::RawValue";
    let escaped: String = token
        .chars()
        .map(|ch| format!("\\u{:04x}", ch as u32))
        .collect();
    assert!(escaped.len() > token.len() * 6 - 1);
    let document = format!(
        r#"{{"x":{{"{escaped}":"{{\"channel\":\"C0SYNTH01\",\"channel\":\"C0OTHER\"}}"}}}}"#
    );
    assert_eq!(
        parse_strict(document.as_bytes()),
        Err(CanonicalError::Malformed),
        "{document}"
    );

    let evaluator = evaluator();
    let smuggled = line_with_raw_arguments(
        &request_for(&evaluator),
        &format!(r#"{{"{escaped}":"{{\"channel\":\"C0SYNTH01\",\"channel\":\"C0OTHER\"}}"}}"#),
    );
    assert_error(&evaluator.evaluate(smuggled.as_bytes()), "malformed");
}

#[test]
fn an_error_result_never_echoes_an_unprintable_request_id() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["request_id"] = "a b\n".into();
    let result = run(&evaluator, &request);
    assert!(result.get("error").is_some(), "{result}");
    assert_eq!(result["request_id"], Value::Null, "{result}");
}

#[test]
fn a_signed_global_lockdown_blocks_every_action_and_no_consent_lowers_it() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut locked = payload("ws-synthetic-1");
    locked["global_lockdown"] = true.into();
    let activation = sign(&signer, &locked);

    let mut request = request_for(&evaluator);
    let identity = identity_of(&evaluator, &request);
    request["activation"] = activation.clone();
    request["saved_consents"] = json!([consent("always-1", "always", &identity)]);
    request["policy"]["rules"] = json!([rule("allow-all", "allow", "*")]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "block", "{result}");
    assert_eq!(result["dispatch_permitted"], false);
    assert_eq!(result["consent_applied"], "none");
    assert!(
        result["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&"global_lockdown".into()),
        "{result}"
    );

    let unlocked = run_with_activation(&evaluator, sign(&signer, &payload("ws-synthetic-1")));
    assert_success(&unlocked);
    assert_ne!(unlocked["action"], "block", "{unlocked}");
}
