use std::cell::RefCell;

use serde_json::{json, Value};

use super::{apply, ALERT_PREFERENCES_KEY};
use crate::cloud_bundle_fetch::SyncError;

#[derive(Default)]
struct Recorder {
    calls: RefCell<Vec<(String, Value)>>,
    saves: RefCell<Vec<(String, Value, String)>>,
}

impl Recorder {
    fn run(&self, advisories: &[Value], preferences: Option<&Value>) -> Result<i64, SyncError> {
        let call = |method: &str, args: Value| -> Result<Value, SyncError> {
            let count = args["payloads"].as_array().map_or(0, Vec::len);
            self.calls.borrow_mut().push((method.to_owned(), args));
            Ok(if method == "cache_advisories" {
                Value::from(count)
            } else {
                Value::Null
            })
        };
        let save = |key: &str, value: &Value, now: &str| -> Result<(), SyncError> {
            self.saves
                .borrow_mut()
                .push((key.to_owned(), value.clone(), now.to_owned()));
            Ok(())
        };
        apply(
            &call,
            &save,
            advisories,
            preferences,
            "2026-01-02T03:04:05+00:00",
        )
    }

    fn events(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|(method, _)| method == "add_event")
            .map(|(_, args)| {
                assert_eq!(args["event_name"], "premium_advisory");
                assert_eq!(args["occurred_at"], "2026-01-02T03:04:05+00:00");
                args["payload_json"].as_str().expect("text").to_owned()
            })
            .collect()
    }
}

#[test]
fn repeated_advisories_are_cached_and_announced_once() {
    let recorder = Recorder::default();
    let first = json!({"artifactId": "pkg:a", "severity": "high", "reason": "bad"});
    let same_reordered = json!({"reason": "bad", "severity": "high", "artifactId": "pkg:a"});
    let stored = recorder
        .run(&[first, same_reordered, json!("not an advisory")], None)
        .expect("applied");
    assert_eq!(stored, 1);
    let calls = recorder.calls.borrow();
    assert_eq!(calls[0].0, "cache_advisories");
    assert_eq!(
        calls[0].1["payloads"],
        json!(["{\"artifactId\": \"pkg:a\", \"reason\": \"bad\", \"severity\": \"high\"}"])
    );
    drop(calls);
    assert_eq!(
        recorder.events(),
        [
            "{\"artifact_id\": \"pkg:a\", \"artifact_name\": \"pkg:a\", \"severity\": \"high\", \"reason\": \"bad\"}"
        ]
    );
}

#[test]
fn an_advisory_without_an_artifact_is_cached_but_not_announced() {
    let recorder = Recorder::default();
    let advisories = [
        json!({"artifactId": "  ", "severity": "low"}),
        json!({"artifactId": "pkg:b", "artifactName": "B", "severity": " "}),
    ];
    assert_eq!(recorder.run(&advisories, None).expect("applied"), 2);
    assert_eq!(
        recorder.events(),
        ["{\"artifact_id\": \"pkg:b\", \"artifact_name\": \"B\", \"severity\": null, \"reason\": null}"]
    );
}

#[test]
fn preferences_are_stored_and_can_turn_advisory_events_off() {
    let recorder = Recorder::default();
    let off = json!({"advisoriesEnabled": false, "watchlistEnabled": true});
    recorder
        .run(&[json!({"artifactId": "pkg:c"})], Some(&off))
        .expect("applied");
    assert!(recorder.events().is_empty());
    let saves = recorder.saves.borrow();
    assert_eq!(saves.len(), 1);
    assert_eq!(saves[0].0, ALERT_PREFERENCES_KEY);
    assert_eq!(saves[0].1, off);
}

#[test]
fn no_preferences_store_an_empty_object_and_no_advisories_skip_the_cache() {
    let recorder = Recorder::default();
    assert_eq!(recorder.run(&[], None).expect("applied"), 0);
    assert!(recorder.calls.borrow().is_empty());
    let saves = recorder.saves.borrow();
    assert_eq!(saves[0].0, ALERT_PREFERENCES_KEY);
    assert_eq!(saves[0].1, json!({}));
}

#[test]
fn an_invalid_cache_answer_fails_the_sync() {
    let call = |_: &str, _: Value| -> Result<Value, SyncError> { Ok(Value::Null) };
    let save = |_: &str, _: &Value, _: &str| -> Result<(), SyncError> { Ok(()) };
    let failed = apply(&call, &save, &[json!({"id": "x"})], None, "now");
    assert!(
        matches!(failed, Err(SyncError::Failed(reason)) if reason == "native_advisory_cache_invalid")
    );
}
