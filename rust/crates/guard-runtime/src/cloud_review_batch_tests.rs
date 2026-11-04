use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn ask(request: Value) -> Value {
    dispatch(&request).expect("cloud_review_batch answers")
}

fn event(sequence: i64, padding: usize) -> Value {
    json!({
        "eventId": format!("event-{sequence}"),
        "localStreamSequence": sequence,
        "padding": "x".repeat(padding),
    })
}

/// The body `post_review_events` sends for `events`, as Python encodes it.
fn body_len(events: &[Value]) -> i64 {
    let body = json!({
        "protocolVersion": 2,
        "firstSequence": events[0]["localStreamSequence"],
        "lastSequence": events[events.len() - 1]["localStreamSequence"],
        "events": events,
    });
    serde_json::to_string(&body).expect("body").len() as i64
}

fn select(events: &[Value], limit_events: i64, limit_bytes: i64) -> Value {
    ask(json!({
        "op": "select",
        "events": events,
        "limit_events": limit_events,
        "limit_bytes": limit_bytes,
    }))
}

#[test]
fn the_longest_prefix_that_fits_the_exact_body_is_selected() {
    let events: Vec<Value> = (1..80).map(|sequence| event(sequence, 80)).collect();
    let three = body_len(&events[..3]);
    assert_eq!(select(&events, 50, three), json!({"count": 3}));
    assert_eq!(select(&events, 50, three - 1), json!({"count": 2}));
    assert_eq!(select(&events, 2, three), json!({"count": 2}));
    assert_eq!(
        select(&events, 50, body_len(&events[..1]) - 1),
        json!({"too_large": true})
    );
    assert_eq!(select(&events, 0, three), json!({"too_large": true}));
    assert_eq!(select(&[], 50, three), json!({"count": 0}));

    // Non-ASCII text is sent escaped, six bytes a character.
    let wide = vec![json!({"localStreamSequence": 7, "note": "é"})];
    let ascii = vec![json!({"localStreamSequence": 7, "note": "abcdef"})];
    let limit = body_len(&ascii);
    assert_eq!(select(&wide, 50, limit), json!({"count": 1}));
    assert_eq!(select(&wide, 50, limit - 1), json!({"too_large": true}));
}

#[test]
fn an_event_without_a_valid_sequence_is_refused_before_it_is_sized() {
    let message = json!({"error": super::ERR_SEQUENCE});
    for sequence in [
        json!(0),
        json!(-1),
        json!(1.0),
        json!(true),
        json!("1"),
        Value::Null,
    ] {
        let events = vec![event(1, 0), json!({"localStreamSequence": sequence})];
        assert_eq!(select(&events, 50, 10), json!({"too_large": true}));
        assert_eq!(select(&events, 50, 1 << 20), message);
    }
    // Events past the limit are never read.
    let events = vec![event(1, 0), json!({"localStreamSequence": 0})];
    assert_eq!(select(&events, 1, 1 << 20), json!({"count": 1}));
    assert_eq!(
        dispatch(&json!({"op": "select", "events": [1], "limit_events": 5, "limit_bytes": 9})),
        Err(ERR_INVALID)
    );
}

fn limits(events: i64, bytes: i64, event_cap: i64) -> Value {
    json!({"events": events, "bytes": bytes, "event_cap": event_cap})
}

fn next(current: Value, response: Value) -> Value {
    ask(json!({"op": "next", "limits": current, "response": response}))
}

#[test]
fn limits_grow_within_what_cloud_advertises() {
    let defaults = limits(50, 512 * 1024, 250);
    let grown = next(defaults, json!({}));
    assert_eq!(grown, limits(100, 512 * 1024, 250));
    let advertised = next(
        grown,
        json!({"maxBatchEvents": 75, "maxBatchBytes": 200_000}),
    );
    assert_eq!(advertised, limits(75, 200_000, 75));
    let hostile = next(
        advertised,
        json!({"maxBatchEvents": 10_000, "maxBatchBytes": 10_000_000}),
    );
    assert_eq!(hostile, limits(150, 512 * 1024, 250));
    let ignored = next(
        limits(10, 1000, 20),
        json!({"maxBatchEvents": 5.0, "maxBatchBytes": true}),
    );
    assert_eq!(ignored, limits(20, 1000, 20));
}

#[test]
fn saved_limits_apply_only_to_their_binding() {
    let persisted = |state: Value| ask(json!({"op": "limits", "state": state, "binding_key": "b"}));
    let defaults = limits(50, 512 * 1024, 250);
    assert_eq!(persisted(json!({})), defaults);
    assert_eq!(
        persisted(json!({"batch_binding_key": "other", "batch_events": 9})),
        defaults
    );
    assert_eq!(
        persisted(json!({
            "batch_binding_key": "b",
            "batch_events": 400,
            "batch_max_bytes": 1 << 30,
            "batch_event_cap": 120,
        })),
        limits(120, 512 * 1024, 120)
    );
    assert_eq!(
        persisted(json!({
            "batch_binding_key": "b",
            "batch_events": -1,
            "batch_max_bytes": "9",
            "batch_event_cap": 30,
        })),
        limits(30, 512 * 1024, 30)
    );
}

fn settle(response: Value, keys: Value) -> Value {
    let sequences: Vec<i64> = (0..keys.as_array().expect("keys").len() as i64)
        .map(|index| 11 + index)
        .collect();
    ask(
        json!({"op": "settle", "response": response, "sequences": sequences, "snapshot_keys": keys}),
    )
}

#[test]
fn per_event_results_settle_each_event() {
    let keys = json!([["r1", 3], ["r2", 4], ["r2", 9], ["r2", 7], ["r2", 5]]);
    let results = json!([
        {"index": 0, "accepted": true},
        {"index": 1.0, "accepted": false, "code": "stale_sequence"},
        {"index": 2, "accepted": false, "code": "review_event_snapshot_required"},
        {"index": true, "accepted": false, "code": "review_event_snapshot_required"},
        {"index": 4, "accepted": false, "error": "stale event sequence 3"},
    ]);
    let answer = settle(
        json!({
            "accepted": 1.9,
            "rejected": 4,
            "delivered": 1,
            "retryAfterMs": 250,
            "perEventResults": results,
        }),
        keys.clone(),
    );
    // An index Python would not equal to its position drops back to the counts.
    assert_eq!(answer["plan"], "rejected");
    assert!(answer.get("acknowledged").is_none());

    let mut results = results;
    results[3]["index"] = json!(3);
    let answer = settle(
        json!({
            "accepted": 1.9,
            "rejected": 4,
            "delivered": 2,
            "retryAfterMs": 250,
            "perEventResults": results,
        }),
        keys,
    );
    assert_eq!(
        answer,
        json!({
            "accepted": 1,
            "rejected": 4,
            "delivered": 0,
            "retry_after_ms": 250,
            "plan": "per_event",
            "acknowledged": [11, 12, 15],
            "retry": [13, 14],
            "retry_results": [results[2], results[3]],
            "snapshot_repairs": {"r2": 9},
        })
    );
}

#[test]
fn superseded_refreshes_are_acknowledged() {
    for item in [
        json!({"index": 0, "accepted": false, "code": "stale_sequence"}),
        json!({"index": 0, "accepted": false, "error": "decision_queued"}),
        json!({"index": 0, "accepted": false, "error": "stale_regression_rejected"}),
        json!({"index": 0, "accepted": false, "error": "stale_sequence"}),
        json!({"index": 0, "accepted": false, "error": "stale event sequence 4"}),
    ] {
        let answer = settle(
            json!({"accepted": 0, "rejected": 1, "perEventResults": [item]}),
            json!([[null, null]]),
        );
        assert_eq!(answer["acknowledged"], json!([11]), "{item}");
        assert_eq!(answer["retry"], json!([]));
    }
}

#[test]
fn counts_decide_the_batch_without_per_event_results() {
    let keys = json!([[null, null], [null, null]]);
    let plan = |response: Value| settle(response, keys.clone())["plan"].clone();
    assert_eq!(plan(json!({"accepted": 2, "rejected": 0})), "acknowledge");
    assert_eq!(plan(json!({"accepted": 2.0})), "acknowledge");
    assert_eq!(plan(json!({"accepted": 1, "rejected": 1})), "rejected");
    assert_eq!(plan(json!({"accepted": 1})), "count_mismatch");
    assert_eq!(plan(json!({"accepted": "2"})), "count_mismatch");
    // A list of the wrong length, or counts that disagree with it, fall back.
    assert_eq!(
        plan(json!({"accepted": 2, "perEventResults": [{"index": 0, "accepted": true}]})),
        "acknowledge"
    );
    assert_eq!(
        plan(json!({
            "accepted": 1,
            "rejected": 1,
            "perEventResults": [{"index": 0, "accepted": true}, {"index": 1, "accepted": true}],
        })),
        "rejected"
    );
    let answer = settle(
        json!({"accepted": true, "rejected": 1, "delivered": true, "retryAfterMs": -5}),
        keys,
    );
    assert_eq!(
        answer,
        json!({"accepted": 1, "rejected": 1, "delivered": 0, "retry_after_ms": 0, "plan": "rejected"})
    );
}

#[test]
fn malformed_requests_are_refused() {
    for request in [
        json!({"op": "forget"}),
        json!({"op": "limits", "state": {}}),
        json!({"op": "limits", "state": [], "binding_key": "b"}),
        json!({"op": "next", "limits": {"events": 1}, "response": {}}),
        json!({"op": "settle", "response": {}, "sequences": [1], "snapshot_keys": []}),
        json!({"op": "select", "events": [], "limit_events": 1.0, "limit_bytes": 1, "extra": 1}),
        json!(["select"]),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
