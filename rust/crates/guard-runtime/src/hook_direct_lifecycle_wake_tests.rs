use super::super::lifecycle::records_only;
use super::{lane, run_as, HOME};
use serde_json::json;

#[test]
fn a_new_session_that_wakes_cigar_still_gets_the_constant() {
    let lane = lane("lifecycle-session-start", json!({}));
    for harness in ["codex", "claude-code"] {
        let start = json!({ "hook_event_name": "SessionStart", "session_id": "synthetic" });
        let result = run_as(&lane, harness, Some(HOME), start);
        assert_eq!(result["outcome"], "answer", "{harness}: {result}");
        assert_eq!(
            result["edge"]["harness_response"]["reason_code"], "native_hook_event_unavailable",
            "{harness}: {result}"
        );
        assert!(!records_only(harness, &lane.fixture.store), "{harness}");
    }
}

#[test]
fn a_finished_turn_that_wakes_cigar_still_gets_the_constant() {
    let lane = lane("lifecycle-turn-stop-wake", json!({}));
    // Claude Code's Stop also closes the turn in Guard's event log.
    rusqlite::Connection::open(lane.fixture.root.join("guard.db"))
        .unwrap()
        .execute_batch(
            "create table guard_events (
                 event_name text not null, payload_json text not null, occurred_at text not null
             );",
        )
        .unwrap();
    for harness in ["codex", "claude-code"] {
        let stop = json!({ "hook_event_name": "Stop", "session_id": "synthetic" });
        let result = run_as(&lane, harness, Some(HOME), stop);
        assert_eq!(result["outcome"], "answer", "{harness}: {result}");
        assert_eq!(
            result["edge"]["harness_response"]["reason_code"], "native_hook_event_unavailable",
            "{harness}: {result}"
        );
        assert!(!records_only(harness, &lane.fixture.store), "{harness}");
    }
}

#[test]
fn a_new_session_in_watch_leaves_cigar_resting() {
    let lane = lane(
        "lifecycle-session-start-watch",
        json!({ "harness_postures": { "codex": "watch" } }),
    );
    assert!(records_only("codex", &lane.fixture.store));
    assert!(!records_only("claude-code", &lane.fixture.store));
    let result = run_as(
        &lane,
        "codex",
        Some(HOME),
        json!({ "hook_event_name": "SessionStart", "session_id": "synthetic" }),
    );
    assert_eq!(result["outcome"], "answer", "{result}");
}
