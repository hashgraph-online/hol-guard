//! Strict request intake and binding resolution.

use super::*;

// ---- strict request intake ----

#[test]
fn duplicate_keys_are_rejected_at_any_depth() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let line = line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","channel":"C0SYNTH02"}"#);
    assert_error(&evaluator.evaluate(line.as_bytes()), "duplicate_key");
    let nested = line_with_raw_arguments(
        &base,
        r#"{"channel":"C0SYNTH01","a":{"b":[{"c":1,"c":2}]}}"#,
    );
    assert_error(&evaluator.evaluate(nested.as_bytes()), "duplicate_key");
    let top_level = base
        .to_string()
        .replacen('{', "{\"request_id\":\"req-0009\",", 1);
    assert_error(&evaluator.evaluate(top_level.as_bytes()), "duplicate_key");
    // An escaped spelling is the same key.
    let escaped = line_with_raw_arguments(
        &base,
        r#"{"channel":"C0SYNTH01","\u0063hannel":"C0SYNTH02"}"#,
    );
    assert_error(&evaluator.evaluate(escaped.as_bytes()), "duplicate_key");
}

#[test]
fn deeply_nested_requests_are_rejected() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let deep = format!(
        "{{\"channel\":\"C0SYNTH01\",\"x\":{}1{}}}",
        "[".repeat(40),
        "]".repeat(40)
    );
    let line = line_with_raw_arguments(&base, &deep);
    assert_error(&evaluator.evaluate(line.as_bytes()), "too_deep");
    let unclosed = "[".repeat(100_000);
    assert_error(&evaluator.evaluate(unclosed.as_bytes()), "too_deep");
}

#[test]
fn nesting_up_to_the_limit_parses_and_one_more_does_not() {
    let nest = |levels: usize| format!("{}1{}", "[".repeat(levels), "]".repeat(levels));
    assert!(parse_strict(nest(MAX_DEPTH).as_bytes()).is_ok());
    assert_eq!(
        parse_strict(nest(MAX_DEPTH + 1).as_bytes()),
        Err(CanonicalError::TooDeep)
    );
    let objects = |levels: usize| format!("{}1{}", "{\"k\":".repeat(levels), "}".repeat(levels));
    assert!(parse_strict(objects(MAX_DEPTH).as_bytes()).is_ok());
    assert_eq!(
        parse_strict(objects(MAX_DEPTH + 1).as_bytes()),
        Err(CanonicalError::TooDeep)
    );
}

#[test]
fn non_integral_and_out_of_range_numbers_are_rejected() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    for number in [
        "1.5",
        "1.0",
        "-0.5",
        "1e2",
        "1E2",
        "1e400",
        "9007199254740992",
        "-9007199254740992",
        "12345678901234567890",
        "123456789012345678901234567890",
    ] {
        let line = line_with_raw_arguments(
            &base,
            &format!("{{\"channel\":\"C0SYNTH01\",\"n\":{number}}}"),
        );
        assert_error(&evaluator.evaluate(line.as_bytes()), "unsupported_number");
    }
    let nested = line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","a":[{"b":0.1}]}"#);
    assert_error(&evaluator.evaluate(nested.as_bytes()), "unsupported_number");
}

#[test]
fn integers_inside_the_safe_range_are_accepted_and_normalized() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    for number in [
        "0",
        "-0",
        "7",
        "-7",
        "9007199254740991",
        "-9007199254740991",
    ] {
        let line = line_with_raw_arguments(
            &base,
            &format!("{{\"channel\":\"C0SYNTH01\",\"n\":{number}}}"),
        );
        assert_success(&evaluator.evaluate(line.as_bytes()));
    }
    let zero = serde_json::from_str::<Value>("-0").unwrap();
    assert_eq!(canonical_bytes(&zero).unwrap(), b"0");
    let limit = serde_json::from_str::<Value>("9007199254740991").unwrap();
    assert_eq!(canonical_bytes(&limit).unwrap(), b"9007199254740991");
}

#[test]
fn arguments_over_64_kib_are_rejected_and_the_limit_is_exact() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    let overhead = canonical_bytes(&json!({"channel": "C0SYNTH01", "text": ""}))
        .unwrap()
        .len();
    let exact = "a".repeat(MAX_ARGUMENT_BYTES - overhead);
    request["action"]["arguments"]["text"] = exact.clone().into();
    assert_success(&run(&evaluator, &request));
    request["action"]["arguments"]["text"] = format!("{exact}a").into();
    assert_error(&run(&evaluator, &request), "too_large");
    request["action"]["arguments"]["text"] = "a".repeat(1024 * 1024).into();
    assert_error(&run(&evaluator, &request), "too_large");
}

#[test]
fn arguments_must_be_an_object() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    for arguments in [json!([]), json!("channel"), json!(1), json!(null)] {
        request["action"]["arguments"] = arguments;
        assert_error(&run(&evaluator, &request), "malformed");
    }
}

#[test]
fn unknown_and_missing_fields_are_invalid_requests() {
    let evaluator = evaluator();
    let edits: [(&str, Edit); 10] = [
        ("top level", |r| r["extra"] = 1.into()),
        ("principal", |r| r["principal"]["role"] = "admin".into()),
        ("connection", |r| r["connection"]["scopes"] = json!(["all"])),
        ("action effect", |r| r["action"]["effect"] = "read".into()),
        ("policy", |r| r["policy"]["default"] = "allow".into()),
        ("missing policy", |r| {
            r.as_object_mut().unwrap().remove("policy");
        }),
        ("missing consents", |r| {
            r.as_object_mut().unwrap().remove("saved_consents");
        }),
        ("bad timestamp", |r| r["evaluated_at"] = "2026-11-01".into()),
        ("bad account digest", |r| {
            r["connection"]["account_digest"] = "abc".into()
        }),
        ("blank label", |r| r["principal"]["subject_id"] = "".into()),
    ];
    for (name, edit) in edits {
        let mut request = request_for(&evaluator);
        edit(&mut request);
        let result = run(&evaluator, &request);
        assert_error(&result, "invalid_request");
        assert!(result["error"]["code"] == "invalid_request", "{name}");
    }
}

#[test]
fn a_wrong_or_missing_schema_is_an_unsupported_version() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["schema"] = "guard.cloud-action-evaluation.v2".into();
    assert_error(&run(&evaluator, &request), "unsupported_version");
    request["schema"] = 1.into();
    assert_error(&run(&evaluator, &request), "unsupported_version");
    request.as_object_mut().unwrap().remove("schema");
    assert_error(&run(&evaluator, &request), "unsupported_version");
    // The version check comes before the field check, so a future request
    // with new fields is reported as a version problem.
    let mut future = request_for(&evaluator);
    future["schema"] = "guard.cloud-action-evaluation.v2".into();
    future["new_field"] = true.into();
    assert_error(&run(&evaluator, &future), "unsupported_version");
}

#[test]
fn a_missing_or_malformed_resource_argument_is_an_invalid_request() {
    let evaluator = evaluator();
    for arguments in [
        json!({"text": "hello"}),
        json!({"channel": 7}),
        json!({"channel": ""}),
        json!({"channel": "has space"}),
        json!({"channel": {"id": "C0SYNTH01"}}),
    ] {
        let mut request = request_for(&evaluator);
        request["action"]["arguments"] = arguments;
        assert_error(&run(&evaluator, &request), "invalid_request");
    }
}

#[test]
fn malformed_json_is_rejected_without_a_request_id() {
    let evaluator = evaluator();
    for line in ["", "   ", "not json", "{", "{}{}", "[1,2", "null", "7"] {
        let result = evaluator.evaluate(line.as_bytes());
        assert_eq!(result["action"], "block", "{line:?}");
        assert_eq!(result["dispatch_permitted"], false, "{line:?}");
        assert!(result["error"]["code"].is_string(), "{line:?}");
    }
    assert_error(&evaluator.evaluate(b""), "malformed");
    assert_error(&evaluator.evaluate(b"{} trailing"), "malformed");
    assert_error(&evaluator.evaluate(&[0xff, 0xfe, 0x7b]), "malformed");
    assert_eq!(evaluator.evaluate(b"{")["request_id"], Value::Null);
}

#[test]
fn arbitrary_bytes_never_panic_and_always_block() {
    let evaluator = evaluator();
    let base = request_for(&evaluator).to_string().into_bytes();
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..400 {
        let mut line = base.clone();
        for _ in 0..=(round % 5) {
            let at = (next() as usize) % line.len();
            match next() % 3 {
                0 => line[at] = (next() & 0xff) as u8,
                1 => line.truncate(at),
                _ => line.insert(at, b"{}[]\",:\\0e-."[(next() % 12) as usize]),
            }
            if line.is_empty() {
                line.push(b'{');
            }
        }
        let result = evaluator.evaluate(&line);
        if result.get("error").is_some() {
            assert_eq!(result["action"], "block");
            assert_eq!(result["dispatch_permitted"], false);
        }
    }
}

// ---- binding resolution ----

#[test]
fn a_binding_set_digest_mismatch_is_binding_unavailable() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["binding_set_digest"] = "0".repeat(64).into();
    let result = run(&evaluator, &request);
    assert_error(&result, "binding_unavailable");
    assert_eq!(result["request_id"], "req-0001");
    request["binding_set_digest"] = "".into();
    assert_error(&run(&evaluator, &request), "binding_unavailable");
}

#[test]
fn an_unknown_action_is_action_unknown() {
    let evaluator = evaluator();
    for action_id in [
        "slack.chat.delete_message",
        "slack.chat",
        "SLACK.CHAT.POST_MESSAGE",
        "slack.*",
    ] {
        let mut request = request_for(&evaluator);
        set_action(&mut request, action_id, json!({"channel": "C0SYNTH01"}));
        assert_error(&run(&evaluator, &request), "action_unknown");
    }
}

#[test]
fn a_provider_mismatch_is_connection_mismatch() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["connection"]["provider"] = "example".into();
    assert_error(&run(&evaluator, &request), "connection_mismatch");
}

#[test]
fn a_caller_cannot_give_an_unknown_action_a_known_effect() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    set_action(
        &mut request,
        "slack.channels.purge",
        json!({"channel": "C0SYNTH01"}),
    );
    request["policy"]["rules"] = json!([rule("allow-all", "allow", "*")]);
    assert_error(&run(&evaluator, &request), "action_unknown");
}

#[test]
fn evaluation_is_stateless_and_repeatable() {
    let evaluator = evaluator();
    let request = request_for(&evaluator);
    let first = run(&evaluator, &request);
    let second = run(&evaluator, &request);
    assert_eq!(first, second);
    assert_error(&evaluator.evaluate(b"{"), "malformed");
    assert_eq!(run(&evaluator, &request), first);
}
