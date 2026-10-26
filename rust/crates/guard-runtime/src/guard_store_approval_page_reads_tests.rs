//! Replays approval queue page, count and next-request vectors recorded from
//! the original Python implementation (see
//! `testdata/guard_store/record_approval_page_read_vectors.py`). Seeds,
//! results and errors all come from Python, never from Rust output. Python
//! still decodes the page cursor, so the replay passes the recorded marker.

use serde_json::{json, Value};

use crate::guard_store_approval_reads::tests::{expected, normalized, seed, store_call};
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_page_read_vectors.json");

/// Every chunk of one page, merged as `GuardStore.list_approval_request_page`
/// returns it.
fn page(home: &std::path::Path, source: &str, call: &Value) -> Result<Value, (String, String)> {
    let args = &call["args"];
    let mut items = Vec::new();
    let mut after = Value::Null;
    loop {
        let mut chunk = store_call(
            home,
            source,
            "list_approval_request_page",
            json!({
                "status": args["status"],
                "limit": args["limit"],
                "cursor": call["cursor_marker"],
                "harness": args["harness"],
                "search": args["search"],
                "include_totals": args["include_totals"],
                "exclude_watch_only": args["exclude_watch_only"],
                "taken": items.len(),
                "after": after,
            }),
        )?;
        let returned = chunk["items"].as_array().unwrap().clone();
        assert!(
            !returned.is_empty() || items.is_empty(),
            "a continued page returns items"
        );
        items.extend(returned);
        let fields = chunk.as_object_mut().unwrap();
        after = fields.remove("after").unwrap_or(Value::Null);
        if fields.remove("complete") == Some(Value::Bool(true)) {
            fields.insert("items".to_owned(), Value::Array(items));
            return Ok(chunk);
        }
    }
}

fn count(home: &std::path::Path, source: &str, call: &Value) -> Result<Value, (String, String)> {
    let args = &call["args"];
    store_call(
        home,
        source,
        "count_approval_requests",
        json!({
            "status": args["status"],
            "harness": args["harness"],
            "search": args["search"],
            "resolved_at_from": args["resolved_at_from"],
            "resolved_at_before": args["resolved_at_before"],
            "exclude_watch_only": args["exclude_watch_only"],
        }),
    )
}

#[test]
fn replays_every_recorded_approval_page_read() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-approval-page-read-vectors.v1"
    );
    let source = vectors["source"].as_str().unwrap();
    let long_string = vectors["long_string"].as_u64().unwrap() as usize;
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(&format!("approval-page-read-{name}"));
        seed(&home.join("guard.db"), &vectors, scenario);
        for (index, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index}");
            let actual = match call["method"].as_str().unwrap() {
                "count" => count(&home, source, call),
                "next" => store_call(
                    &home,
                    source,
                    "get_next_pending_request",
                    json!({"exclude_ids": call["args"]["exclude_ids"]}),
                ),
                _ if call["cursor_marker"].is_null() && !call["args"]["cursor"].is_null() => {
                    // Python rejects an undecodable cursor before the store call.
                    continue;
                }
                _ => page(&home, source, call),
            };
            let actual = actual.map(|value| normalized(value, long_string));
            assert_eq!(actual, expected(call, long_string), "{label}");
            replayed += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(replayed >= 150, "replayed {replayed} calls");
}
