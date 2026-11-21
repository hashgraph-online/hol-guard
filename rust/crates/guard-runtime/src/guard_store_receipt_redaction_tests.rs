//! The bookkeeping rules answer as the runner's Python helpers did.

use std::collections::BTreeMap;

use serde_json::json;

use super::*;

#[derive(Default)]
pub(crate) struct Memory {
    pub(crate) rows: BTreeMap<String, Value>,
    pub(crate) requeues: Vec<(String, String)>,
    pub(crate) events: Vec<(String, String)>,
}

impl Bookkeeping for Memory {
    fn read(&mut self, key: &str) -> StoreResult<Option<Value>> {
        Ok(self.rows.get(key).cloned())
    }

    fn write(&mut self, key: &str, payload: &Value, _now: &str) -> StoreResult<()> {
        self.rows.insert(key.to_owned(), payload.clone());
        Ok(())
    }

    fn delete(&mut self, key: &str) -> StoreResult<()> {
        self.rows.remove(key);
        Ok(())
    }

    fn requeue_projection(&mut self, level: &str, changed_at: &str) -> StoreResult<i64> {
        self.requeues
            .push((level.to_owned(), changed_at.to_owned()));
        self.rows.insert(
            PRIVACY_PROJECTION_MARKER.to_owned(),
            json!({"level": level, "updated_at": changed_at, "requeued": 0}),
        );
        Ok(0)
    }

    fn add_event(&mut self, name: &str, payload_json: &str, _now: &str) -> StoreResult<()> {
        self.events.push((name.to_owned(), payload_json.to_owned()));
        Ok(())
    }
}

const T1: &str = "2026-08-03T00:01:00Z";
const T2: &str = "2026-08-03T00:02:00Z";

#[test]
fn relaxing_the_level_restarts_the_cursor_and_requeues_the_projection() {
    let mut store = Memory::default();
    persist(&mut store, "none", "full", T1).unwrap();
    assert_eq!(
        store.rows[CURSOR_KEY],
        json!({
            "last_rowid": 0,
            "synced_at": T1,
            "reason": "cloud_receipt_redaction_level_relaxed",
            "receipt_redaction_level": "none",
        })
    );
    assert_eq!(
        store.rows[LEVEL_KEY],
        json!({"level": "none", "updated_at": T1})
    );
    assert_eq!(
        store.rows[RELAXED_RESYNC_MARKER],
        json!({"level": "none", "updated_at": T1})
    );
    assert_eq!(store.requeues, vec![("none".to_owned(), T1.to_owned())]);
}

#[test]
fn an_unchanged_level_neither_restarts_nor_requeues() {
    let mut store = Memory::default();
    persist(&mut store, "partial", "full", T1).unwrap();
    store.rows.remove(CURSOR_KEY);
    store.requeues.clear();
    persist(&mut store, "partial", "full", T2).unwrap();
    assert!(!store.rows.contains_key(CURSOR_KEY));
    assert!(store.requeues.is_empty());
    assert_eq!(
        store.rows[LEVEL_KEY],
        json!({"level": "partial", "updated_at": T2})
    );
}

#[test]
fn tightening_the_level_requeues_without_a_cursor_restart() {
    let mut store = Memory::default();
    persist(&mut store, "full", "none", T1).unwrap();
    assert!(!store.rows.contains_key(CURSOR_KEY));
    assert!(!store.rows.contains_key(RELAXED_RESYNC_MARKER));
    assert_eq!(store.requeues, vec![("full".to_owned(), T1.to_owned())]);
}

#[test]
fn an_invalid_stored_level_falls_back_to_the_local_level() {
    let mut store = Memory::default();
    store
        .rows
        .insert(LEVEL_KEY.to_owned(), json!({"level": "bogus"}));
    persist(&mut store, "full", "full", T1).unwrap();
    assert!(store.requeues.is_empty());
}

#[test]
fn reset_applies_the_local_level_and_drops_the_relaxation_markers() {
    let mut store = Memory::default();
    persist(&mut store, "none", "full", T1).unwrap();
    store.rows.insert(
        COMMAND_DETAIL_BACKFILL_MARKER.to_owned(),
        json!({"done": true}),
    );
    store.requeues.clear();
    reset(&mut store, "full", T2).unwrap();
    assert_eq!(
        store.rows[LEVEL_KEY],
        json!({"level": "full", "updated_at": T2})
    );
    assert!(!store.rows.contains_key(RELAXED_RESYNC_MARKER));
    assert!(!store.rows.contains_key(COMMAND_DETAIL_BACKFILL_MARKER));
    assert_eq!(store.requeues, vec![("full".to_owned(), T2.to_owned())]);
}

#[test]
fn reset_without_a_stored_level_does_not_requeue() {
    let mut store = Memory::default();
    reset(&mut store, "partial", T1).unwrap();
    assert!(store.requeues.is_empty());
    assert_eq!(
        store.rows[LEVEL_KEY],
        json!({"level": "partial", "updated_at": T1})
    );
}

#[test]
fn the_projection_is_requeued_only_when_its_marker_names_another_level() {
    let mut store = Memory::default();
    ensure_projection(&mut store, "none", T1).unwrap();
    ensure_projection(&mut store, "none", T2).unwrap();
    assert_eq!(store.requeues, vec![("none".to_owned(), T1.to_owned())]);
    ensure_projection(&mut store, "full", T2).unwrap();
    assert_eq!(store.requeues.len(), 2);
}

#[test]
fn an_existing_relaxed_level_restarts_the_cursor_once() {
    let mut store = Memory::default();
    ensure_resync(&mut store, "full", T1).unwrap();
    assert!(store.rows.is_empty());
    ensure_resync(&mut store, "partial", T1).unwrap();
    assert_eq!(
        store.rows[CURSOR_KEY]["reason"],
        json!("cloud_receipt_redaction_level_relaxed_existing")
    );
    store.rows.remove(CURSOR_KEY);
    ensure_resync(&mut store, "partial", T2).unwrap();
    assert!(!store.rows.contains_key(CURSOR_KEY));
}

#[test]
fn the_projection_marker_text_matches_the_python_requeue() {
    assert_eq!(
        projection_marker("none", T1, 3).unwrap(),
        "{\"level\": \"none\", \"updated_at\": \"2026-08-03T00:01:00Z\", \"requeued\": 3}"
    );
    assert_eq!(
        projection_marker("caf\u{e9}", T1, 0).unwrap(),
        "{\"level\": \"caf\\u00e9\", \"updated_at\": \"2026-08-03T00:01:00Z\", \"requeued\": 0}"
    );
}

#[test]
fn the_method_rejects_an_unknown_action_and_an_invalid_level() {
    let connection = Connection::open_in_memory().unwrap();
    let run = |args: Value| {
        let Value::Object(args) = args else {
            unreachable!()
        };
        method(&connection, "hol-guard", &Args(&args))
    };
    assert!(run(json!({"action": "other", "now": T1})).is_err());
    assert!(run(json!({"action": "ensure_resync", "level": "loose", "now": T1})).is_err());
}

fn sync_state_only() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (
               state_key text primary key, payload_json text not null,
               updated_at text not null);",
        )
        .unwrap();
    connection
}

fn args(value: Value) -> serde_json::Map<String, Value> {
    let Value::Object(map) = value else {
        unreachable!()
    };
    map
}

#[test]
fn a_matching_or_full_ensure_check_is_a_no_op_read() {
    let connection = sync_state_only();
    let noop = |value: Value| is_noop(&connection, &Args(&args(value))).unwrap();
    assert!(noop(
        json!({"action": "ensure_resync", "level": "full", "now": T1})
    ));
    assert!(!noop(
        json!({"action": "ensure_resync", "level": "none", "now": T1})
    ));
    assert!(!noop(
        json!({"action": "ensure_projection", "level": "none", "now": T1})
    ));
    assert!(!noop(
        json!({"action": "persist", "level": "none", "local_level": "none", "now": T1})
    ));
    assert!(!noop(
        json!({"action": "ensure_resync", "level": "loose", "now": T1})
    ));
    write_encoded(
        &connection,
        PRIVACY_PROJECTION_MARKER,
        "{\"level\": \"none\", \"requeued\": 0}",
        T1,
    )
    .unwrap();
    write_encoded(
        &connection,
        RELAXED_RESYNC_MARKER,
        "{\"level\": \"none\"}",
        T1,
    )
    .unwrap();
    assert!(noop(
        json!({"action": "ensure_projection", "level": "none", "now": T2})
    ));
    assert!(!noop(
        json!({"action": "ensure_projection", "level": "full", "now": T2})
    ));
    assert!(noop(
        json!({"action": "ensure_resync", "level": "none", "now": T2})
    ));
}

#[test]
fn a_failed_requeue_rolls_back_the_cursor_and_level_written_before_it() {
    // Without the Review outbox tables the requeue fails after the cursor and
    // level rows are written; the store transaction must undo both.
    let connection = sync_state_only();
    write_encoded(&connection, CURSOR_KEY, "{\"last_rowid\": 17}", T1).unwrap();
    write_encoded(&connection, LEVEL_KEY, "{\"level\": \"full\"}", T1).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    let request =
        args(json!({"action": "persist", "level": "none", "local_level": "full", "now": T2}));
    assert!(method(&connection, "hol-guard", &Args(&request)).is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        read_payload(&connection, CURSOR_KEY).unwrap(),
        Some(json!({"last_rowid": 17}))
    );
    assert_eq!(
        read_payload(&connection, LEVEL_KEY).unwrap(),
        Some(json!({"level": "full"}))
    );
    assert_eq!(
        read_payload(&connection, RELAXED_RESYNC_MARKER).unwrap(),
        None
    );
}
