use super::super::ReadConfig;
use super::*;
use crate::guard_store_approval_reads::tests::{expected, normalized, seed};
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_page_read_vectors.json");

struct Store {
    config: ReadConfig,
    reads: NativeReads,
    vectors: Value,
    scenario: Value,
}

/// A store seeded with one recorded page scenario.
fn store(name: &str) -> Store {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == name)
        .unwrap()
        .clone();
    let home = temp_home(&format!("edge-requests-{name}"));
    seed(&home.join("guard.db"), &vectors, &scenario);
    let handshake = json!({
        "schema": super::super::HANDSHAKE_SCHEMA,
        "auth_token": "requests-test-secret",
        "guard_home": home.to_str().unwrap(),
        "store_path": home.join("guard.db").to_str().unwrap(),
        "source": vectors["source"],
        "busy_timeout_ms": 2000,
    });
    Store {
        config: ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap(),
        reads: NativeReads::new(None),
        vectors,
        scenario,
    }
}

fn query_for(args: &Value) -> String {
    let mut fields = vec![format!("limit={}", args["limit"])];
    fields.push(format!(
        "status={}",
        args["status"].as_str().unwrap_or("all")
    ));
    fields.join("&")
}

#[test]
fn rejects_options_as_the_native_handler_rejects_them() {
    let store = store("page_empty");
    for (query, error) in [
        ("limit=0", "invalid_limit"),
        ("limit=abc", "invalid_limit"),
        ("status=open", "invalid_status"),
    ] {
        assert_eq!(
            list(query, false, &store.config, &store.reads),
            Some((400, json!({"error": error}), false)),
            "{query}"
        );
    }
}

#[test]
fn relays_every_cursor_to_the_daemon() {
    let store = store("page_empty");
    assert_eq!(list("cursor=abc", true, &store.config, &store.reads), None);
}

#[test]
fn hosted_pages_match_the_recorded_store_pages() {
    for name in ["page_mixed", "page_chain", "page_browser", "page_empty"] {
        let store = store(name);
        let long_string = store.vectors["long_string"].as_u64().unwrap() as usize;
        let call = &store.scenario["calls"][0];
        let (status, body, no_store) =
            list(&query_for(&call["args"]), true, &store.config, &store.reads).unwrap();
        assert_eq!((status, no_store), (200, true), "{name}");
        assert_eq!(
            Ok(normalized(body, long_string)),
            expected(call, long_string),
            "{name}"
        );
    }
}

#[test]
fn other_harnesses_skip_the_native_queue() {
    let store = store("page_empty");
    let (status, body, no_store) =
        list("harness=codex", false, &store.config, &store.reads).unwrap();
    assert_eq!((status, no_store), (200, true));
    assert!(body.get("native_business_queue_checked").is_none());
    assert_eq!(body["items"], json!([]));
}

#[test]
fn a_local_page_without_a_runtime_directory_goes_to_the_daemon() {
    let store = store("page_empty");
    assert_eq!(list("", false, &store.config, &store.reads), None);
}

#[test]
fn reads_the_queue_answer_as_the_daemon_reader_does() {
    let empty = json!({"schema": QUEUE_SCHEMA, "version": 1, "items": []});
    assert_eq!(queue_answer_empty(&empty), Some(true));
    for missing in [
        json!({"error": "native_policy_snapshot_missing"}),
        json!({"error": "native_policy_snapshot_unavailable", "retryable": true}),
    ] {
        assert_eq!(queue_answer_empty(&missing), Some(true), "{missing}");
    }
    for relayed in [
        json!({"schema": QUEUE_SCHEMA, "version": 1, "items": [{"request_id": "a"}]}),
        json!({"schema": QUEUE_SCHEMA, "version": true, "items": []}),
        json!({"schema": QUEUE_SCHEMA, "version": 2, "items": []}),
        json!({"schema": "other", "version": 1, "items": []}),
        json!({"schema": QUEUE_SCHEMA, "version": 1, "items": [], "extra": 1}),
        json!({"error": "native_policy_snapshot_missing", "retryable": "yes"}),
        json!({"error": "native_store_failed"}),
        json!([]),
    ] {
        assert_eq!(queue_answer_empty(&relayed), None, "{relayed}");
    }
}
