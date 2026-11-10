use super::super::ReadConfig;
use super::*;
use crate::guard_store_approval_reads::tests::{expected, normalized, seed};
use crate::guard_store_cmd_vectors_tests::temp_home;

const LOCAL: Option<std::net::SocketAddr> = Some(std::net::SocketAddr::V4(
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 5474),
));
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
        "cwd": "/",
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
fn a_cursor_no_page_names_asks_for_a_refresh() {
    let store = store("page_empty");
    for cursor in ["abc", "native-business-v1:x:0", "e30", "%%%"] {
        let (status, body, no_store) = list(
            &format!("cursor={cursor}"),
            true,
            &store.config,
            &store.reads,
        )
        .unwrap();
        assert_eq!((status, no_store), (400, false), "{cursor}");
        assert_eq!(body["recovery"]["code"], "refresh_queue");
    }
}

#[test]
fn store_cursors_name_their_page_marker() {
    // {"last_seen_at":"t","request_id":"r"}
    let cursor = "eyJsYXN0X3NlZW5fYXQiOiJ0IiwicmVxdWVzdF9pZCI6InIifQ";
    assert_eq!(page_marker(cursor), Some(json!(["t", "r"])));
    assert_eq!(page_marker(&format!("{cursor}==")), Some(json!(["t", "r"])));
    assert_eq!(page_marker("e30"), None);
    assert_eq!(page_marker("a"), None);
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

/// Store reads run on the edge connection worker, not the test runner's much
/// larger default stack. Keep the populated-page path on that actual budget.
#[test]
fn populated_pages_fit_the_connection_worker_stack() {
    let store = store("page_mixed");
    std::thread::Builder::new()
        .name("edge-page-stack-regression".into())
        .stack_size(super::super::super::CONNECTION_THREAD_STACK)
        .spawn(move || {
            let call = &store.scenario["calls"][0];
            let (status, body, no_store) =
                list(&query_for(&call["args"]), true, &store.config, &store.reads)
                    .expect("native page response");
            assert_eq!((status, no_store), (200, true));
            let long_string = store.vectors["long_string"].as_u64().unwrap() as usize;
            assert_eq!(
                Ok(normalized(body, long_string)),
                expected(call, long_string)
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn reads_a_recorded_resume_and_leaves_seeding_to_the_daemon() {
    let store = store("page_mixed");
    let (_, page, _) = list("", true, &store.config, &store.reads).unwrap();
    let request_id = page["items"][0]["request_id"].as_str().unwrap().to_owned();
    assert_eq!(resume(&request_id, &store.config, &store.reads), None);
    assert_eq!(
        resume("missing", &store.config, &store.reads),
        Some((404, json!({"error": "not_found"})))
    );
    let home = store.config.guard_home.clone();
    rusqlite::Connection::open(std::path::Path::new(&home).join("guard.db"))
        .unwrap()
        .execute(
            "insert into guard_request_resumes (request_id, harness, strategy, status,
                 created_at, updated_at)
             values (?1, 'codex', 'manual-only', 'skipped', 't1', 't2')",
            [&request_id],
        )
        .unwrap();
    let (status, body) = resume(&request_id, &store.config, &store.reads).unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["request_id"], json!(request_id));
    assert_eq!(body["strategy"], "manual-only");
    assert_eq!(
        Some(body),
        store.reads.store_call(
            &store.config,
            "get_request_resume",
            json!({"request_id": request_id}),
        )
    );
}

#[test]
fn hosted_details_drop_the_private_queue_hint() {
    let store = store("page_mixed");
    let (_, page, _) = list("", true, &store.config, &store.reads).unwrap();
    let request_id = page["items"][0]["request_id"].as_str().unwrap().to_owned();
    let (status, body, no_store) =
        detail(&request_id, "", true, LOCAL, &store.config, &store.reads).unwrap();
    assert_eq!(status, 200);
    assert!(!no_store);
    assert_eq!(body["request_id"], json!(request_id));
    assert!(body.get("extension_allow_hint").is_none());
}

#[test]
fn a_local_detail_without_a_resident_view_drops_the_hint_and_waits_go_to_the_daemon() {
    let store = store("page_mixed");
    let (_, page, _) = list("", true, &store.config, &store.reads).unwrap();
    let request_id = page["items"][0]["request_id"].as_str().unwrap().to_owned();
    let (status, body, _) =
        detail(&request_id, "", false, LOCAL, &store.config, &store.reads).unwrap();
    assert_eq!(status, 200);
    assert!(body.get("extension_allow_hint").is_none());
    assert!(body.get("extension_recommendation").is_none());
    assert_eq!(
        detail(
            &request_id,
            "wait_ms=10",
            true,
            LOCAL,
            &store.config,
            &store.reads
        ),
        None
    );
}

#[test]
fn a_hosted_unknown_id_gets_the_local_queue_link() {
    let store = store("page_mixed");
    let (status, body, no_store) =
        detail("missing", "", true, LOCAL, &store.config, &store.reads).unwrap();
    assert_eq!((status, no_store), (404, false));
    assert_eq!(body["error"], "not_found");
    assert_eq!(body["recovery"]["code"], "request_unknown");
    assert_eq!(
        body["recovery"]["queue_url"],
        "http://127.0.0.1:5474/#/inbox"
    );
}

#[test]
fn a_local_id_no_snapshot_could_name_is_not_found() {
    let store = store("page_mixed");
    let (status, body, _) =
        detail("bad id!", "", false, LOCAL, &store.config, &store.reads).unwrap();
    assert_eq!(status, 404);
    assert_eq!(body["recovery"]["code"], "request_unknown");
}

#[test]
fn rows_the_daemon_may_offer_a_grant_on_go_to_the_daemon() {
    let offer = |row: Value| may_carry_grant_offer(row.as_object().unwrap());
    assert!(offer(json!({"browser_intent": {}})));
    assert!(offer(
        json!({"scanner_evidence": [1, {"source": "trusted_local_tool"}]})
    ));
    assert!(!offer(json!({"browser_intent": null})));
    assert!(!offer(
        json!({"browser_intent": "x", "scanner_evidence": {"source": "trusted_local_tool"}})
    ));
    assert!(!offer(json!({"scanner_evidence": [{"source": "other"}]})));
}
