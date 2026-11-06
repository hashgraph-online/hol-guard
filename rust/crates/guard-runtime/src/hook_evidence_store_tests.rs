//! The evidence store seam answers the recorded Python wire exactly. Every
//! scenario in `testdata/guard_store/command_activity_vectors.json` is replayed
//! in order: the steps the writer reaches through [`EvidenceStoreApi`] go
//! through the adapter and are compared against what Python recorded, and the
//! remaining steps go straight to the resident so the stored state advances the
//! way the recording did.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use guard_command::hook_evidence_writer::{CorrelationHandle, EvidenceStoreApi, SqliteTimeoutApi};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{NativeEvidenceStore, PolicyBarrierApi};
use crate::guard_store_cmd_vectors_tests::{
    assert_rows, build_database, dump, run_step, temp_home,
};
use crate::guard_store_db::StoreError;
use crate::hook_evidence_store_gate::{hold_storage_gate, STORAGE_GATE_FILE_NAME};
use crate::hook_evidence_store_timeout::{
    internal_hook_timeout_ms, sqlite_timeout_ms, NativeSqliteTimeout,
};
use crate::hook_evidence_store_wire::{
    python_title, python_truthy, store_failure, validated_invocation_preview,
};
use crate::local_store_read::STORE_FILE_NAME;

const VECTORS: &str = include_str!("../testdata/guard_store/command_activity_vectors.json");

/// A barrier that only counts. None of the command-activity methods moves
/// provider authority, so a notification from this scenario set is a defect.
struct CountingBarrier(Arc<AtomicUsize>);

impl PolicyBarrierApi for CountingBarrier {
    fn notify_policy_mutation(&self, _guard_home: &Path) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn new_store(home: &Path, source: &str) -> (NativeEvidenceStore, Arc<AtomicUsize>) {
    let notifications = Arc::new(AtomicUsize::new(0));
    let store = NativeEvidenceStore::new(
        home.to_path_buf(),
        source,
        Box::new(CountingBarrier(Arc::clone(&notifications))),
    );
    (store, notifications)
}

fn handle(wire: &Value) -> CorrelationHandle {
    CorrelationHandle {
        kind: wire["kind"].as_str().unwrap().to_owned(),
        harness: wire["harness"].as_str().unwrap().to_owned(),
        key_id: wire["key_id"].as_str().unwrap().to_owned(),
        digest: wire["digest"].as_str().unwrap().to_owned(),
    }
}

fn map(args: &Value, key: &str) -> Map<String, Value> {
    args[key].as_object().unwrap().clone()
}

/// What the adapter answers for one recorded step, or `None` when the writer
/// never reaches that method — or reaches it with arguments this seam does not
/// produce, such as a shadow evaluation.
fn through_adapter(
    store: &NativeEvidenceStore,
    step: &Value,
) -> Option<Result<Value, std::io::Error>> {
    let args = &step["wire_args"];
    Some(match step["method"].as_str().unwrap() {
        "record_command_activity" => {
            // The writer records a decided command, never a shadow evaluation.
            if !args["shadow"].is_null() || args["shadow_evaluation_succeeded"] != json!(false) {
                return None;
            }
            store
                .record_command_activity(
                    &map(args, "evidence"),
                    args["invocation_preview"].as_str(),
                )
                .map(Value::from)
        }
        "is_exact_command_activity_pre_replay" => store
            .is_exact_command_activity_pre_replay(&map(args, "evidence"))
            .map(Value::from),
        "get_command_activity_by_request_correlation" => store
            .command_activity_by_request_correlation(&handle(&args["correlation"]))
            .map(|row| row.map_or(Value::Null, Value::Object)),
        "transition_command_activity" => store
            .transition_command_activity(&map(args, "current"))
            .map(Value::from),
        "record_command_activity_observation_conflict" => store
            .record_command_activity_observation_conflict(args["occurred_at"].as_str().unwrap())
            // The method answers nothing; only the table state is recorded.
            .map(|()| step["result"].clone()),
        _ => return None,
    })
}

#[test]
fn replays_every_recorded_step_the_writer_reaches_through_this_seam() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let order_by = vectors["order_by"].as_object().unwrap();
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(&format!("evidence-store-{name}"));
        build_database(&home.join("guard.db"), &vectors, scenario);
        let (store, notifications) = new_store(&home, source);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {}", step["method"]);
            if step["method"] == "sql" {
                crate::guard_store_cmd_vectors_tests::apply_sql(&home, step);
            } else if step["python_side"] != true {
                match through_adapter(&store, step) {
                    None => {
                        run_step(&home, source, step);
                    }
                    Some(answer) => {
                        replayed += 1;
                        match step["error"].as_object() {
                            None => {
                                let payload =
                                    answer.unwrap_or_else(|error| panic!("{label}: {error}"));
                                // The Python wrappers narrow a flag result with
                                // `bool()`; a row result is compared as recorded.
                                let recorded = match payload {
                                    Value::Bool(_) => Value::from(python_truthy(&step["result"])),
                                    _ => step["result"].clone(),
                                };
                                assert_eq!(payload, recorded, "{label}");
                            }
                            Some(error) => {
                                let failure = answer.unwrap_err().to_string();
                                let message = error["message"].as_str().unwrap();
                                assert!(failure.contains(message), "{label}: {failure}");
                            }
                        }
                    }
                }
            }
            for (table, rows) in step["post_changed"].as_object().unwrap() {
                expected.insert(table.clone(), rows.clone());
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for (table, key) in order_by {
                assert_rows(
                    &dump(&connection, table, key.as_str().unwrap()),
                    &expected[table],
                    &format!("{label}: {table}"),
                );
            }
        }
        assert_eq!(
            notifications.load(Ordering::SeqCst),
            0,
            "{name}: barrier closed"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
    assert_eq!(replayed, 50, "adapter-owned recorded steps");
}

#[test]
fn a_store_call_takes_the_gate_and_leaves_it_private() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = &vectors["scenarios"][0];
    let home = temp_home("evidence-store-gate-mode");
    build_database(&home.join("guard.db"), &vectors, scenario);
    let (store, _notifications) = new_store(&home, vectors["source"].as_str().unwrap());
    let row = store
        .command_activity_by_request_correlation(&CorrelationHandle {
            kind: "request".to_owned(),
            harness: "codex".to_owned(),
            key_id: "key.v1".to_owned(),
            digest: "f".repeat(64),
        })
        .unwrap();
    assert!(row.is_none());
    let gate = home.join(STORAGE_GATE_FILE_NAME);
    assert!(gate.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&gate).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn the_gate_waits_for_an_exclusive_hold_and_then_gives_up() {
    use fs2::FileExt;

    let home: PathBuf = temp_home("evidence-store-gate-wait");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(home.join(STORAGE_GATE_FILE_NAME))
        .unwrap();
    FileExt::lock_exclusive(&held).unwrap();
    let failure = hold_storage_gate(&home, std::time::Duration::from_millis(30)).unwrap_err();
    assert_eq!(failure.kind(), std::io::ErrorKind::TimedOut);
    FileExt::unlock(&held).unwrap();
    // A gate nobody holds exclusively is shared straight away.
    hold_storage_gate(&home, std::time::Duration::from_millis(30)).unwrap();
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn an_installed_timeout_wins_and_is_restored_when_it_is_dropped() {
    let before = sqlite_timeout_ms();
    let guard =
        NativeSqliteTimeout.sqlite_timeout_override(std::num::NonZeroU32::new(1_234).unwrap());
    assert_eq!(sqlite_timeout_ms(), 1_234);
    drop(guard);
    assert_eq!(sqlite_timeout_ms(), before);
}

#[test]
fn the_internal_hook_bound_takes_integers_and_caps_them() {
    assert_eq!(internal_hook_timeout_ms(" 120 "), Some(120));
    assert_eq!(internal_hook_timeout_ms("900"), Some(250));
    assert_eq!(internal_hook_timeout_ms("0"), None);
    assert_eq!(internal_hook_timeout_ms("-5"), None);
    assert_eq!(internal_hook_timeout_ms("120.5"), None);
    assert_eq!(internal_hook_timeout_ms("120ms"), None);
    assert_eq!(internal_hook_timeout_ms(""), None);
}

#[test]
fn a_preview_is_trimmed_or_refused_never_truncated() {
    assert!(validated_invocation_preview(None).unwrap().is_none());
    assert_eq!(
        validated_invocation_preview(Some("  git push  ")).unwrap(),
        Some("git push".to_owned())
    );
    let too_long = "x".repeat(4_097);
    for refused in ["", "   ", "git\0push", too_long.as_str()] {
        assert_eq!(
            validated_invocation_preview(Some(refused))
                .unwrap_err()
                .to_string(),
            "invalid_invocation_preview"
        );
    }
    // The bound counts characters, the way Python's `len` counts text.
    let at_bound = "é".repeat(4_096);
    assert!(validated_invocation_preview(Some(at_bound.as_str())).is_ok());
}

#[test]
fn the_source_label_capitalizes_each_run_of_letters() {
    assert_eq!(python_title("claude-code"), "Claude-Code");
    assert_eq!(python_title("codex"), "Codex");
    assert_eq!(python_title("ZED"), "Zed");
    assert_eq!(python_title("gpt_4o"), "Gpt_4O");
}

#[test]
fn a_null_answer_is_false_the_way_python_reads_it() {
    assert!(!python_truthy(&Value::Null));
    assert!(!python_truthy(&json!(false)));
    assert!(!python_truthy(&json!(0)));
    assert!(!python_truthy(&json!("")));
    assert!(!python_truthy(&json!([])));
    assert!(!python_truthy(&json!({})));
    assert!(python_truthy(&json!(true)));
    assert!(python_truthy(&json!({ "activity_id": "a" })));
}

/// A store whose file is not a database fails every call the same way, so the
/// seam records it once for the client that owns `GuardStore` recovery.
#[test]
fn an_unreadable_store_reports_one_fatal_failure() {
    let home = temp_home("evidence-store-fatal");
    std::fs::write(home.join(STORE_FILE_NAME), b"this is not a database").unwrap();
    let (store, _) = new_store(&home, "oauth");
    let correlation = CorrelationHandle {
        kind: "command".to_owned(),
        harness: "claude-code".to_owned(),
        key_id: "key".to_owned(),
        digest: "digest".to_owned(),
    };

    assert_eq!(store.fatal().peek(), Value::Null);
    assert!(store
        .command_activity_by_request_correlation(&correlation)
        .is_err());
    let reported = store.fatal().peek();
    assert_eq!(reported["code"], json!("native_guard_store_sqlite_corrupt"));
    // Reporting it does not clear it: the reply carrying it can be lost, and
    // the recovery it asks for can fail, so it waits to be acknowledged.
    assert_eq!(store.fatal().peek(), reported);
    // A second failure behind the first is the same quarantine, so the
    // identifier the client is recovering from does not change under it.
    assert!(store
        .command_activity_by_request_correlation(&correlation)
        .is_err());
    assert_eq!(store.fatal().peek(), reported);

    // An acknowledgement for a failure this slot never held leaves it waiting.
    store.fatal().acknowledge("fatal-does-not-exist");
    assert_eq!(store.fatal().peek(), reported);

    store.fatal().acknowledge(reported["id"].as_str().unwrap());
    assert_eq!(store.fatal().peek(), Value::Null);
}

/// An acknowledgement that outlived the resident which issued it must not
/// clear a failure a later resident recorded.
#[test]
fn an_identifier_from_another_process_is_not_acknowledged() {
    let home = temp_home("evidence-store-fatal-nonce");
    std::fs::write(home.join(STORE_FILE_NAME), b"this is not a database").unwrap();
    let (store, _) = new_store(&home, "oauth");
    let correlation = CorrelationHandle {
        kind: "command".to_owned(),
        harness: "claude-code".to_owned(),
        key_id: "key".to_owned(),
        digest: "digest".to_owned(),
    };

    assert!(store
        .command_activity_by_request_correlation(&correlation)
        .is_err());
    let reported = store.fatal().peek();
    let id = reported["id"].as_str().unwrap().to_owned();

    // The counter alone used to name the failure, so the first failure of
    // every resident was `fatal-1`. A client that recovered from one
    // resident's `fatal-1` would have cleared the next resident's.
    assert_ne!(id, "fatal-1");
    store.fatal().acknowledge("fatal-1");
    assert_eq!(store.fatal().peek(), reported);

    // The process's own identifier still clears it.
    store.fatal().acknowledge(&id);
    assert_eq!(store.fatal().peek(), Value::Null);
}

/// An ordinary failed call is not a reason to quarantine the store.
#[test]
fn a_refused_argument_is_not_a_fatal_failure() {
    let home = temp_home("evidence-store-not-fatal");
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = &vectors["scenarios"][0];
    build_database(&home.join(STORE_FILE_NAME), &vectors, scenario);
    let (store, _) = new_store(&home, "oauth");

    assert!(store.transition_command_activity(&Map::new()).is_err());
    assert_eq!(store.fatal().peek(), Value::Null);
}

/// The writer waits out a busy store and gives up on other refusals, so a
/// lock has to reach it as a timeout and nothing else may.
#[test]
fn only_a_busy_store_fails_as_a_timeout() {
    let sqlite = |code| {
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            None,
        ))
    };
    for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
        let failure = store_failure("record_native_decision_receipt", &sqlite(code));
        assert_eq!(failure.kind(), std::io::ErrorKind::TimedOut);
    }
    let failure = store_failure(
        "record_native_decision_receipt",
        &sqlite(rusqlite::ffi::SQLITE_CONSTRAINT),
    );
    assert_eq!(failure.kind(), std::io::ErrorKind::Other);
}
