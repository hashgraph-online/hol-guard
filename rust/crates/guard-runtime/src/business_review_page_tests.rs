use serde_json::{json, Value};

use super::dispatch;

const PENDING: &str = "30c8b7d6f38fa64da22d34df01bf11ebff96d7bf21bbea543ce0f55b7bfeaba1";
const RESOLVED: &str = "442c38c44686c2a48d8aa4b89dca6de5750ede24bb6d4713832927b127c6c42a";

fn summaries() -> Value {
    json!([
        {"request_id": "r1", "operation": "mail_read"},
        {"request_id": "r2", "operation": "mail_send"},
        {"request_id": "r3", "operation": "drive_read"},
    ])
}

fn page(extra: Value) -> Value {
    let mut args =
        json!({"summaries": summaries(), "status": "pending", "harness": null, "search": null});
    for (key, value) in extra.as_object().expect("object") {
        args[key] = value.clone();
    }
    dispatch(&args).expect("answer")
}

fn ids(answer: &Value) -> Vec<&str> {
    answer["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["request_id"].as_str().expect("id"))
        .collect()
}

#[test]
fn a_saved_request_is_a_display_only_row() {
    let answer = page(json!({}));
    assert_eq!(answer["count"], json!(3));
    assert_eq!(answer["next_cursor"], Value::Null);
    let row = &answer["items"][1];
    assert_eq!(row["artifact_id"], json!("r2"));
    assert_eq!(row["artifact_name"], json!("Send mail"));
    assert_eq!(row["queue_preview"], json!("Send mail"));
    assert_eq!(row["harness"], json!("native-business"));
    assert_eq!(row["policy_action"], json!("require-reapproval"));
    assert_eq!(row["native_business_review_display_only"], json!(true));
    assert_eq!(row["allowed_scopes"], json!([]));
    assert_eq!(row["publisher"], Value::Null);
    assert_eq!(row.as_object().expect("row").len(), 26);
}

#[test]
fn the_harness_and_search_filters_match_the_queue() {
    assert_eq!(page(json!({"harness": "codex"}))["count"], json!(0));
    assert_eq!(
        page(json!({"harness": "native-business"}))["count"],
        json!(3)
    );
    assert_eq!(page(json!({"harness": ""}))["count"], json!(3));
    assert_eq!(ids(&page(json!({"search": "SEND"}))), ["r2"]);
    assert_eq!(ids(&page(json!({"search": "r3"}))), ["r3"]);
    assert_eq!(page(json!({"search": "saved native"}))["count"], json!(3));
    assert_eq!(page(json!({"search": "zzz"}))["count"], json!(0));
}

#[test]
fn the_rows_fill_the_last_sql_page_and_continue_by_cursor() {
    let first = page(json!({"room": 1}));
    assert_eq!(ids(&first), ["r1"]);
    assert_eq!(
        first["next_cursor"],
        json!(format!("native-business-v1:{PENDING}:1"))
    );
    assert_eq!(page(json!({"room": 0}))["items"], json!([]));
    assert_eq!(page(json!({"room": 5}))["next_cursor"], Value::Null);

    let second = page(json!({"cursor": format!("native-business-v1:{PENDING}:1"), "limit": 1}));
    assert_eq!(ids(&second), ["r2"]);
    assert_eq!(
        second["next_cursor"],
        json!(format!("native-business-v1:{PENDING}:2"))
    );
    let last = page(json!({"cursor": format!("native-business-v1:{PENDING}:2"), "limit": 5}));
    assert_eq!(ids(&last), ["r3"]);
    assert_eq!(last["next_cursor"], Value::Null);
    assert_eq!(last["count"], json!(3));
}

#[test]
fn a_cursor_the_rows_cannot_continue_is_refused() {
    let expired = page(json!({"cursor": format!("native-business-v1:{PENDING}:3"), "limit": 1}));
    assert_eq!(expired, json!({"error": "expired_cursor"}));
    for cursor in [
        format!("native-business-v1:{RESOLVED}:1"),
        format!("native-business-v1:{PENDING}:0012"),
        format!("native-business-v1:{PENDING}:"),
        format!("native-business-v1:{PENDING}:1:2"),
        format!("native-business-v1:{PENDING}:+1"),
        format!("native-business-v1:{PENDING}"),
        format!("{PENDING}:1"),
    ] {
        assert_eq!(
            page(json!({"cursor": cursor, "limit": 1})),
            json!({"error": "invalid_cursor"}),
            "{cursor}"
        );
    }
    let resolved = page(json!({
        "status": "resolved",
        "cursor": format!("native-business-v1:{RESOLVED}:1"),
        "limit": 1,
    }));
    assert_eq!(resolved, json!({"error": "invalid_cursor"}));
}

#[test]
fn a_malformed_request_is_refused() {
    assert!(dispatch(&json!([])).is_err());
    assert!(dispatch(&json!({"status": "pending"})).is_err());
    let unknown = json!({"summaries": [{"request_id": "r1", "operation": "shell"}]});
    assert!(dispatch(&unknown).is_err());
    let missing = json!({"summaries": [{"operation": "mail_read"}]});
    assert!(dispatch(&missing).is_err());
    for extra in [
        json!({"status": 1}),
        json!({"search": []}),
        json!({"room": -1}),
        json!({"room": 1, "limit": 1}),
        json!({"cursor": "native-business-v1:x:1"}),
        json!({"cursor": 7, "limit": 1}),
        json!({"cursor": "native-business-v1:x:1", "limit": 1, "room": 1}),
    ] {
        let mut args = json!({"summaries": summaries()});
        for (key, value) in extra.as_object().expect("object") {
            args[key] = value.clone();
        }
        assert!(dispatch(&args).is_err(), "{extra}");
    }
}
