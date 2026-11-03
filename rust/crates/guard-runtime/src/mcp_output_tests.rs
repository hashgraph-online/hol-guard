use serde_json::{json, Value};

use super::dispatch;

fn answer(args: Value) -> Value {
    dispatch(&args).expect("sanitized output")
}

#[test]
fn search_keeps_only_allowlisted_fields() {
    let raw = json!({"id": "receipt:abc", "title": "t", "kind": "receipt", "harness": "devin",
                     "decision": "allow", "changedSinceLastApproval": true, "path": "/secret"});
    assert_eq!(
        answer(json!({ "search": [raw] })),
        json!({"results": [{"id": "receipt:abc", "title": "t", "kind": "receipt", "harness": "devin",
                            "decision": "allow", "changedSinceLastApproval": true}]})
    );
}

#[test]
fn enums_fall_back_and_blank_ids_are_dropped() {
    let raw = json!({"id": "", "kind": "secret", "harness": "unknown-agent", "decision": "",
                     "changedSinceLastApproval": "yes"});
    assert_eq!(
        answer(json!({ "search": [raw] })),
        json!({"results": [{"title": "", "kind": "receipt", "harness": "", "decision": "unknown"}]})
    );
}

#[test]
fn text_is_normalized_and_stripped_of_control_characters() {
    let raw = json!({"title": "ｆｕｌｌ\u{0}\u{1b}[31m\u{9b}2J\u{85}\tok\n\r", "id": 7});
    let result = &answer(json!({ "search": [raw] }))["results"][0];
    assert_eq!(result["title"], json!("full[31m2J\tok\n\r"));
    assert_eq!(result["id"], json!("7"));
    let long = json!({"title": "é".repeat(300)});
    let title = answer(json!({ "search": [long] }))["results"][0]["title"].clone();
    assert_eq!(title.as_str().map(|text| text.chars().count()), Some(256));
}

#[test]
fn fetch_text_is_cut_to_the_byte_limit_on_a_character_boundary() {
    let short = answer(json!({"fetch": {"text": "abc", "truncated": 0}}));
    assert_eq!(short["result"]["text"], json!("abc"));
    assert_eq!(short["result"]["truncated"], json!(false));
    let wide = answer(json!({"fetch": {"text": "é".repeat(20_000)}}));
    let text = wide["result"]["text"].as_str().expect("text");
    assert_eq!(text.len(), 32_768);
    assert_eq!(wide["result"]["truncated"], json!(true));
    let split = answer(json!({"fetch": {"text": format!("a{}", "é".repeat(20_000))}}));
    assert_eq!(split["result"]["text"].as_str().map(str::len), Some(32_767));
    let ascii = answer(json!({"fetch": {"text": "a".repeat(40_000)}}));
    assert_eq!(ascii["result"]["text"].as_str().map(str::len), Some(32_768));
    assert_eq!(ascii["result"]["truncated"], json!(true));
    let flagged = answer(json!({"fetch": {"text": "abc", "truncated": "yes"}}));
    assert_eq!(flagged["result"]["truncated"], json!(true));
}

#[test]
fn status_counts_follow_int_and_versions_are_optional() {
    assert_eq!(
        answer(json!({"status": {}})),
        json!({"status": {"cliAvailable": true, "receiptCount": 0, "inventoryCount": 0}})
    );
    assert_eq!(
        answer(
            json!({"status": {"cliAvailable": 0, "receiptCount": 2.9, "inventoryCount": true,
                                 "cliVersion": "3.1", "extra": 1}})
        ),
        json!({"status": {"cliAvailable": false, "receiptCount": 2, "inventoryCount": 1,
                          "cliVersion": "3.1"}})
    );
    assert_eq!(
        answer(json!({"status": {"receiptCount": "4"}}))["status"]["receiptCount"],
        json!(0)
    );
}

#[test]
fn an_unknown_or_oversize_shape_is_refused() {
    assert!(dispatch(&json!({})).is_err());
    assert!(dispatch(&json!({"search": [], "fetch": {}})).is_err());
    assert!(dispatch(&json!({"search": [1]})).is_err());
    assert!(dispatch(&json!({"fetch": []})).is_err());
    assert!(dispatch(&json!({ "search": vec![json!({}); 21] })).is_err());
}
