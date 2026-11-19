use super::*;
use crate::cloud_bundle_sync::BundleStore;
use crate::cloud_event_sync::event_store;
use crate::local_store_read::STORE_FILE_NAME;

#[test]
fn pain_signal_candidates_read_only_the_signal_events_after_the_cursor() {
    let home = tempfile::tempdir().unwrap();
    let connection = rusqlite::Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
    connection
        .execute_batch(
            "create table guard_events (event_id integer primary key, event_name text, \
             payload_json text, occurred_at text);
             insert into guard_events values (1, 'install_time_block', '{\"a\":1}', 't1');
             insert into guard_events values (2, 'receipt_recorded', '{}', 't2');
             insert into guard_events values (3, 'install_time_warn', '[1]', 't3');",
        )
        .unwrap();
    let bundle = BundleStore::new(home.path(), &home.path().join(STORE_FILE_NAME), None);
    let store = event_store(home.path(), &bundle);

    let all = pain_signal_candidates(&store, 0).unwrap();
    let ids: Vec<i64> = all
        .iter()
        .map(|item| item["event_id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [1, 3]);
    assert_eq!(all[0]["payload"], json!({"a": 1}));
    assert_eq!(all[1]["payload"], json!({}));

    let after = pain_signal_candidates(&store, 1).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0]["event_name"], json!("install_time_warn"));
}

#[test]
fn a_small_pain_signal_batch_covers_every_candidate() {
    let candidates: Vec<Value> = (1..=3)
        .map(|id| {
            json!({"event_id": id, "event_name": "install_time_block", "occurred_at": "t", "payload": {}})
        })
        .collect();
    let (covered, _items, counts) = batch_within_body_limit(&candidates, &json!([])).unwrap();
    assert_eq!(covered, 3);
    assert!(counts.is_array());
}
