use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn request(response: Value, events: &[(&str, i64)]) -> Value {
    let event_ids: Vec<&str> = events.iter().map(|(id, _)| *id).collect();
    let sequences: Vec<i64> = events.iter().map(|(_, sequence)| *sequence).collect();
    json!({ "response": response, "event_ids": event_ids, "sequences": sequences })
}

fn answer(response: Value, events: &[(&str, i64)]) -> Value {
    dispatch(&request(response, events)).expect("cloud_review_ack answers")
}

fn error(response: Value, events: &[(&str, i64)]) -> String {
    let answer = answer(response, events);
    answer["error"].as_str().expect("protocol error").to_owned()
}

fn single(status: &str) -> Value {
    let accepted = matches!(status, "accepted" | "duplicate" | "stale");
    json!({
        "protocolVersion": 2,
        "acknowledgedThrough": if accepted { 41 } else { 40 },
        "accepted": i32::from(accepted),
        "rejected": i32::from(!accepted),
        "results": [{ "eventId": "event-41", "status": status, "code": "review_event_rejected" }],
    })
}

const ONE: &[(&str, i64)] = &[("event-41", 41)];

#[test]
fn accepted_events_normalize_in_order() {
    let response = json!({
        "protocolVersion": 2,
        "acknowledgedThrough": 42,
        "accepted": 2,
        "rejected": 0,
        "results": [
            { "eventId": "a", "status": "accepted", "nativeContextCommitted": true },
            { "eventId": "b", "status": "duplicate", "code": "dup" },
        ],
        "extra": "ignored",
    });
    let answer = answer(response, &[("a", 41), ("b", 42)]);
    assert_eq!(
        answer["response"],
        json!({
            "accepted": 2,
            "delivered": 1,
            "rejected": 0,
            "perEventResults": [
                { "index": 0, "accepted": true, "code": null, "error": null, "nativeContextCommitted": true },
                { "index": 1, "accepted": true, "code": "dup", "error": null },
            ],
            "acknowledgedThrough": 42,
            "protocolVersion": 2,
        })
    );
}

#[test]
fn rejected_events_carry_status_error_and_retry_hint() {
    let mut response = single("quarantined");
    response["retryAfterMs"] = json!(500);
    response["results"][0]["retryAfterMs"] = json!(9_000_000_000_u64);
    response["results"][0]["code"] = json!("");
    let answer = answer(response, ONE);
    assert_eq!(
        answer["response"]["perEventResults"][0],
        json!({
            "index": 0,
            "accepted": false,
            "code": "",
            "error": "quarantined",
            "status": "quarantined",
            "retryAfterMs": 3_600_000,
        })
    );
    assert_eq!(answer["response"]["retryAfterMs"], 3_600_000);
    assert_eq!(answer["response"]["delivered"], 0);
}

#[test]
fn a_sequence_collision_names_its_event() {
    let mut response = single("rejected");
    response["results"][0]["code"] = json!("review_event_snapshot_sequence_collision");
    let item = &answer(response, ONE)["response"]["perEventResults"][0];
    assert_eq!(item["eventId"], "event-41");
    assert_eq!(item["error"], "review_event_snapshot_sequence_collision");
    let mut response = single("rejected");
    response["results"][0]["code"] = json!("review_event_sequence_conflict");
    let item = &answer(response, ONE)["response"]["perEventResults"][0];
    assert_eq!(item["eventId"], "event-41");
    let item = &answer(single("rejected"), ONE)["response"]["perEventResults"][0];
    assert!(item.get("eventId").is_none());
}

#[test]
fn context_commit_is_kept_only_for_delivered_events() {
    for (status, kept) in [("accepted", true), ("duplicate", true), ("stale", false)] {
        let mut response = single(status);
        response["results"][0]["nativeContextCommitted"] = json!(true);
        let item = &answer(response, ONE)["response"]["perEventResults"][0];
        assert_eq!(
            item.get("nativeContextCommitted").is_some(),
            kept,
            "{status}"
        );
    }
    let mut response = single("accepted");
    response["results"][0]["nativeContextCommitted"] = json!(1);
    let item = &answer(response, ONE)["response"]["perEventResults"][0];
    assert!(item.get("nativeContextCommitted").is_none());
}

#[test]
fn unsupported_versions_name_the_version_python_would() {
    for (version, rendered) in [
        (Value::Null, "missing"),
        (json!(1), "1"),
        (json!("2"), "2"),
        (json!(3), "3"),
        (json!(2.5), "2.5"),
        (json!(true), "True"),
        (json!(["a", "it's"]), "['a', \"it's\"]"),
        (json!({ "k": null }), "{'k': None}"),
    ] {
        let mut response = single("accepted");
        response["protocolVersion"] = version;
        assert_eq!(
            error(response, ONE),
            format!(
                "Guard Cloud Review returned unsupported protocol version {rendered}. \
                 Update HOL Guard and reconnect Guard Cloud before retrying."
            )
        );
    }
    let mut response = single("accepted");
    response
        .as_object_mut()
        .expect("object")
        .remove("protocolVersion");
    assert!(error(response, ONE).contains("version missing"));
    // Python's `==` lets a float of the same value through.
    let mut response = single("accepted");
    response["protocolVersion"] = json!(2.0);
    assert!(answer(response, ONE).get("response").is_some());
}

#[test]
fn malformed_acknowledgements_are_protocol_errors() {
    let invalid = "Guard Cloud Review returned an invalid protocol 2 acknowledgement. \
                   Update HOL Guard before retrying.";
    for (key, value) in [
        ("results", json!({})),
        ("results", json!([])),
        ("acknowledgedThrough", json!(-1)),
        ("acknowledgedThrough", json!(9_007_199_254_740_992_u64)),
        ("acknowledgedThrough", json!(41.0)),
        ("acknowledgedThrough", json!(true)),
        ("acknowledgedThrough", Value::Null),
    ] {
        let mut response = single("accepted");
        response[key] = value;
        assert_eq!(error(response, ONE), invalid, "{key}");
    }
    let mut response = single("accepted");
    response["results"][0]["eventId"] = json!("event-42");
    assert!(error(response, ONE).contains("for a different event"));
    let mut response = single("accepted");
    response["results"] = json!(["accepted"]);
    assert!(error(response, ONE).contains("for a different event"));
    for status in [
        json!("approved"),
        json!(1),
        Value::Null,
        json!(["accepted"]),
    ] {
        let mut response = single("accepted");
        response["results"][0]["status"] = status;
        assert!(error(response, ONE).contains("unsupported event status"));
    }
    let mut response = single("accepted");
    response["acknowledgedThrough"] = json!(40);
    assert!(error(response, ONE).contains("stopped before an accepted event"));
}

#[test]
fn counts_compare_the_way_python_does() {
    for (accepted, rejected, ok) in [
        (json!(1), json!(0), true),
        (json!(1.0), json!(0), true),
        (json!(true), json!(false), true),
        (json!(2), json!(0), false),
        (json!("1"), json!(0), false),
        (json!(1), Value::Null, false),
    ] {
        let mut response = single("accepted");
        response["accepted"] = accepted;
        response["rejected"] = rejected;
        let answer = answer(response, ONE);
        if ok {
            assert_eq!(answer["response"]["accepted"], 1);
        } else {
            assert!(answer["error"]
                .as_str()
                .is_some_and(|message| message.contains("counts are inconsistent")));
        }
    }
}

#[test]
fn batch_limits_must_be_positive_integers() {
    let mut response = single("accepted");
    response["maxBatchEvents"] = json!(50);
    response["maxBatchBytes"] =
        serde_json::from_str::<Value>("123456789012345678901234").expect("big integer");
    let answer = answer(response, ONE);
    assert_eq!(answer["response"]["maxBatchEvents"], 50);
    assert_eq!(
        answer["response"]["maxBatchBytes"].to_string(),
        "123456789012345678901234"
    );
    let mut response = single("accepted");
    response["maxBatchEvents"] = Value::Null;
    assert!(answer_has_no(&response, "maxBatchEvents"));
    for limit in [json!(0), json!(-1), json!(5.0), json!("5"), json!(true)] {
        let mut response = single("accepted");
        response["maxBatchBytes"] = limit;
        assert!(error(response, ONE).contains("invalid batch limit"));
    }
}

fn answer_has_no(response: &Value, key: &str) -> bool {
    answer(response.clone(), ONE)["response"].get(key).is_none()
}

#[test]
fn retry_hints_ignore_invalid_values() {
    for hint in [json!(0), json!(-5), json!(5.5), json!("5"), json!(true)] {
        let mut response = single("rejected");
        response["retryAfterMs"] = hint.clone();
        response["results"][0]["retryAfterMs"] = hint;
        let answer = answer(response, ONE);
        assert!(answer["response"].get("retryAfterMs").is_none());
        assert!(answer["response"]["perEventResults"][0]
            .get("retryAfterMs")
            .is_none());
    }
    // An accepted event's hint is ignored; the batch hint still counts.
    let mut response = single("accepted");
    response["retryAfterMs"] = json!(250);
    response["results"][0]["retryAfterMs"] = json!(900);
    let answer = answer(response, ONE);
    assert_eq!(answer["response"]["retryAfterMs"], 250);
}

#[test]
fn a_falsy_code_falls_back_to_the_status() {
    for code in [Value::Null, json!(0), json!(false), json!([]), json!({})] {
        let mut response = single("rejected");
        response["results"][0]["code"] = code.clone();
        let item = &answer(response, ONE)["response"]["perEventResults"][0];
        assert_eq!(item["error"], "rejected");
        assert_eq!(item["code"], code);
    }
    let mut response = single("rejected");
    response["results"][0]["code"] = json!({ "nested": 1 });
    let item = &answer(response, ONE)["response"]["perEventResults"][0];
    assert_eq!(item["error"], json!({ "nested": 1 }));
}

#[test]
fn malformed_requests_are_refused() {
    let response = single("accepted");
    for request in [
        json!([]),
        json!({ "response": response, "event_ids": ["event-41"] }),
        json!({ "response": [], "event_ids": ["event-41"], "sequences": [41] }),
        json!({ "response": response, "event_ids": ["event-41"], "sequences": [0] }),
        json!({ "response": response, "event_ids": ["event-41"], "sequences": [41.0] }),
        json!({ "response": response, "event_ids": ["event-41"], "sequences": [41, 42] }),
        json!({ "response": response, "event_ids": "event-41", "sequences": [41] }),
        json!({ "response": response, "event_ids": ["event-41"], "sequences": [41], "x": 1 }),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
