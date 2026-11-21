use super::*;

const DESTINATION: &str = "release transport destination is not permitted";
const LIMIT: &str = "release transport byte limit invalid";
const REDIRECT: &str = "release transport redirect limit or destination invalid";

fn ask(operation: &str, mut fields: Value) -> Value {
    fields["operation"] = operation.into();
    evaluate(&fields).unwrap()
}

fn rejected(message: &str) -> Value {
    json!({"rejected": message})
}

#[test]
fn an_unknown_operation_is_a_hard_error() {
    for input in [
        json!({}),
        json!({"operation": "other"}),
        json!({"operation": 3}),
    ] {
        assert_eq!(evaluate(&input).unwrap_err(), invalid());
    }
}

#[test]
fn only_a_listed_host_over_https_on_the_default_port_may_be_requested() {
    for host in HOSTS {
        for url in [
            format!("https://{host}/a"),
            format!("https://{host}:443/a"),
            format!("https://{host}"),
            format!("https://{host}?page=2"),
        ] {
            let reply = ask("request", json!({"url": url, "maximum": 100}));
            assert_eq!(reply, json!({"permitted": true}), "{url}");
        }
    }
    for url in [
        "http://github.com/a",
        "https://github.com.evil.invalid/a",
        "https://evil.invalid/github.com",
        "https://user:pass@github.com/a",
        "https://github.com@evil.invalid/a",
        "https://evil.invalid\\@github.com/a",
        "https://github.com\\.evil.invalid/a",
        "https://github.com:444/a",
        "https://github.com:0443/a",
        "https://github.com:/a",
        "https://GITHUB.com/a",
        "HTTPS://github.com/a",
        "https://github.com /a",
        "https://github.com\t/a",
        "https://github.com\n/a",
        " https://github.com/a",
        "https://g\u{ee}thub.com/a",
        "file:///tmp/data",
        "//github.com/a",
        "https://",
        "",
    ] {
        let reply = ask("request", json!({"url": url, "maximum": 100}));
        assert_eq!(reply, rejected(DESTINATION), "{url:?}");
    }
}

#[test]
fn the_byte_limit_is_bounded_and_checked_before_the_destination() {
    let url = "https://github.com/a";
    for maximum in [1_u64, 100, 32 * 1024 * 1024] {
        let reply = ask("request", json!({"url": url, "maximum": maximum}));
        assert_eq!(reply, json!({"permitted": true}));
    }
    for maximum in [
        json!(0),
        json!(32 * 1024 * 1024 + 1),
        json!(-1),
        json!(1.5),
        json!(true),
        json!("100"),
        Value::Null,
    ] {
        let reply = ask("request", json!({"url": url, "maximum": maximum}));
        assert_eq!(reply, rejected(LIMIT), "{maximum}");
        let reply = ask("request", json!({"url": "http://x", "maximum": maximum}));
        assert_eq!(reply, rejected(LIMIT), "{maximum}");
    }
    let reply = ask("request", json!({"url": 7, "maximum": 100}));
    assert_eq!(reply, rejected(&invalid()));
}

#[test]
fn a_missing_release_and_a_refused_request_are_answers_not_redirects() {
    let missing = json!({"missing": "extension release is unavailable"});
    assert_eq!(ask("refusal", json!({"status": 404, "hop": 0})), missing);
    for status in [400, 401, 403, 429, 500, 503] {
        let input =
            json!({"status": status, "hop": 0, "location": "/x", "next": "https://github.com/x"});
        assert_eq!(ask("refusal", input), json!({"refused": true}), "{status}");
    }
    assert_eq!(
        ask("refusal", json!({"status": "404", "hop": 0})),
        rejected(&invalid())
    );
}

#[test]
fn a_redirect_is_followed_only_to_a_permitted_destination() {
    let next = "https://release-assets.githubusercontent.com/asset";
    for status in REDIRECTS {
        let input = json!({"status": status, "hop": 0, "location": next, "next": next});
        assert_eq!(ask("refusal", input), json!({"redirect": next}), "{status}");
    }
    let input =
        json!({"status": 302, "hop": 3, "location": "/asset", "next": "https://github.com/asset"});
    assert_eq!(
        ask("refusal", input),
        json!({"redirect": "https://github.com/asset"})
    );
    for next in [
        "https://evil.invalid/asset",
        "http://github.com/asset",
        "https://user:pass@github.com/asset",
        "https://github.com:444/asset",
    ] {
        let input = json!({"status": 302, "hop": 0, "location": next, "next": next});
        assert_eq!(ask("refusal", input), rejected(DESTINATION), "{next}");
    }
}

#[test]
fn a_redirect_without_a_target_or_past_the_hop_limit_is_refused() {
    let next = "https://github.com/asset";
    for input in [
        json!({"status": 302, "hop": 0, "next": next}),
        json!({"status": 302, "hop": 0, "location": null, "next": next}),
        json!({"status": 302, "hop": 0, "location": "", "next": next}),
        json!({"status": 302, "hop": 0, "location": "/asset", "next": null}),
        json!({"status": 302, "hop": 0, "location": "/asset"}),
        json!({"status": 302, "hop": 4, "location": "/asset", "next": next}),
        json!({"status": 302, "hop": 5, "location": "/asset", "next": next}),
        json!({"status": 302, "hop": u64::MAX, "location": "/asset", "next": next}),
    ] {
        assert_eq!(ask("refusal", input.clone()), rejected(REDIRECT), "{input}");
    }
    let input = json!({"status": 302, "location": "/asset", "next": next});
    assert_eq!(ask("refusal", input), rejected(&invalid()));
}

#[test]
fn response_headers_are_bounded_before_the_body_is_read() {
    let headers = |encoding: Value, length: Value| {
        let input = json!({"content_encoding": encoding, "content_length": length, "maximum": 100});
        ask("headers", input)
    };
    let compressed = rejected("compressed release transport is not permitted");
    let declared = |length: Option<u64>| json!({"declared": length});
    assert_eq!(headers(Value::Null, Value::Null), declared(None));
    assert_eq!(headers("identity".into(), "2".into()), declared(Some(2)));
    for encoding in ["gzip", "Identity", "", "identity "] {
        assert_eq!(
            headers(encoding.into(), Value::Null),
            compressed,
            "{encoding:?}"
        );
    }
    assert_eq!(headers(json!(5), Value::Null), rejected(&invalid()));
    for (text, length) in [("1", 1), ("0002", 2), ("100", 100), ("0000000100", 100)] {
        assert_eq!(
            headers(Value::Null, text.into()),
            declared(Some(length)),
            "{text}"
        );
    }
    let exceeds = rejected("release transport content length exceeds byte limit");
    for text in [
        "0",
        "",
        "101",
        "-1",
        "+1",
        "1.0",
        " 1",
        "1 ",
        "\u{663}",
        "99999999999999999999999999",
    ] {
        assert_eq!(headers(Value::Null, text.into()), exceeds, "{text:?}");
    }
    assert_eq!(headers(Value::Null, json!(2)), rejected(&invalid()));
    // An encoding the response may not use is refused before its length is read.
    assert_eq!(headers("gzip".into(), "101".into()), compressed);
}

#[test]
fn the_body_must_fit_the_bound_and_the_length_it_declared() {
    let body = |length: Value, declared: Value| {
        ask(
            "body",
            json!({"length": length, "declared": declared, "maximum": 100}),
        )
    };
    let accepted = json!({"accepted": true});
    for (length, declared) in [(1, None), (100, None), (1, Some(1)), (100, Some(100))] {
        assert_eq!(body(length.into(), json!(declared)), accepted, "{length}");
    }
    let invalid_length = rejected("release transport body length invalid");
    for (length, declared) in [
        (0, None),
        (101, None),
        (1, Some(2)),
        (2, Some(1)),
        (0, Some(0)),
    ] {
        assert_eq!(
            body(length.into(), json!(declared)),
            invalid_length,
            "{length}"
        );
    }
    assert_eq!(body("1".into(), Value::Null), rejected(&invalid()));
    assert_eq!(body(1.into(), "1".into()), rejected(&invalid()));
    let input = json!({"length": 1, "declared": null, "maximum": 0});
    assert_eq!(ask("body", input), rejected(LIMIT));
}

#[test]
fn transient_refusals_and_connection_failures_are_retried_on_a_bounded_schedule() {
    let delay = |status: Value, network: bool, attempt: u64| {
        let input = json!({"status": status, "network": network, "attempt": attempt});
        ask("retry", input)["delay"].clone()
    };
    for status in [429, 500, 502, 503, 504] {
        assert_eq!(delay(json!(status), false, 0), json!(0.5), "{status}");
        assert_eq!(delay(json!(status), false, 1), json!(2.0), "{status}");
        assert_eq!(delay(json!(status), false, 2), Value::Null, "{status}");
        assert_eq!(delay(json!(status), false, u64::MAX), Value::Null);
    }
    for status in [400, 401, 403, 404, 501, 505] {
        assert_eq!(delay(json!(status), false, 0), Value::Null, "{status}");
        // A refusal is judged by its status, whatever else the failure was.
        assert_eq!(delay(json!(status), true, 0), Value::Null, "{status}");
    }
    assert_eq!(delay(Value::Null, true, 0), json!(0.5));
    assert_eq!(delay(Value::Null, true, 1), json!(2.0));
    assert_eq!(delay(Value::Null, true, 2), Value::Null);
    assert_eq!(delay(Value::Null, false, 0), Value::Null);
    let input = json!({"status": null, "network": "yes", "attempt": 0});
    assert_eq!(ask("retry", input), rejected(&invalid()));
    let input = json!({"status": 503, "network": false});
    assert_eq!(ask("retry", input), rejected(&invalid()));
}
