//! Claude Code `Stop` hooks, which end the turn as the daemon's
//! `claude_turn_stop` does before the constant answer.

use super::super::{deferred, lane, run_as, HOME};
use super::{keyed_lane, notice, record_notice, BOUND_KEY, BOUND_KEY_ID};
use serde_json::{json, Value};

fn stop(session: Value) -> Value {
    json!({ "hook_event_name": "Stop", "session_id": session })
}

fn constant() -> Value {
    json!({
        "harness_response": {
            "continue": true,
            "policy_action": "allow",
            "reason_code": "native_hook_event_unavailable",
            "hookSpecificOutput": { "hookEventName": "Stop" },
        }
    })
}

fn turn_stops(connection: &rusqlite::Connection) -> Vec<String> {
    let mut statement = connection
        .prepare(
            "select payload_json from guard_events \
             where event_name = 'claude/turn_stop' order by rowid",
        )
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn state_keys(connection: &rusqlite::Connection) -> Vec<String> {
    let mut statement = connection
        .prepare("select state_key from sync_state order by state_key")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn pending_keys(connection: &rusqlite::Connection, session: &str) -> Vec<String> {
    state_keys(connection)
        .into_iter()
        .filter(|key| {
            key.starts_with(&format!("claude_pending_permission:{session}:"))
                || *key == format!("claude_pending_permissions:{session}")
        })
        .collect()
}

#[test]
fn a_stop_drops_the_sessions_pending_prompts_and_records_the_turn() {
    let (lane, connection) = keyed_lane("stop-keyed");
    for session in ["stopped", "other"] {
        record_notice(
            &lane,
            &BOUND_KEY,
            BOUND_KEY_ID,
            session,
            notice(session, "tool_call"),
        );
    }
    assert_eq!(pending_keys(&connection, "stopped").len(), 2);

    // The daemon strips the session before it builds the key.
    let result = run_as(&lane, "claude-code", Some(HOME), stop(json!(" stopped ")));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(result["edge"], constant());
    assert_eq!(pending_keys(&connection, "stopped"), Vec::<String>::new());
    assert_eq!(pending_keys(&connection, "other").len(), 2);
    // The event copies the session as sent, in the daemon's `json.dumps` form.
    assert_eq!(
        turn_stops(&connection),
        vec!["{\"session_id\": \" stopped \", \"discarded_pending_permissions\": 1}"]
    );

    // A later stop finds nothing left to drop, and a stop without a session
    // drops nothing.
    let mut sessionless = stop(Value::Null);
    sessionless.as_object_mut().unwrap().remove("session_id");
    for payload in [stop(json!("stopped")), sessionless] {
        assert_eq!(
            run_as(&lane, "claude-code", Some(HOME), payload)["edge"],
            constant()
        );
    }
    assert_eq!(
        turn_stops(&connection)[1..],
        [
            "{\"session_id\": \"stopped\", \"discarded_pending_permissions\": 0}",
            "{\"session_id\": null, \"discarded_pending_permissions\": 0}",
        ]
    );
    assert_eq!(pending_keys(&connection, "other").len(), 2);
}

#[test]
fn a_stop_without_the_bound_key_drops_only_what_it_can_verify() {
    let lane = lane("stop-unkeyed", json!({}));
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table sync_state (
                 state_key text primary key, payload_json text not null, updated_at text not null
             );
             create table guard_events (
                 event_name text not null, payload_json text not null, occurred_at text not null
             );",
        )
        .unwrap();
    record_notice(
        &lane,
        &BOUND_KEY,
        BOUND_KEY_ID,
        "unkeyed",
        notice("unkeyed", "tool_call"),
    );
    let before = state_keys(&connection);

    // Only the daemon's key verifies the index, so the daemon drops it.
    assert_eq!(
        deferred(&run_as(
            &lane,
            "claude-code",
            Some(HOME),
            stop(json!("unkeyed"))
        )),
        "direct_hook_permission_notice"
    );
    assert_eq!(state_keys(&connection), before);
    assert_eq!(turn_stops(&connection), Vec::<String>::new());

    // A session with no index has nothing to verify.
    let result = run_as(&lane, "claude-code", Some(HOME), stop(json!("idle")));
    assert_eq!(result["edge"], constant(), "{result}");
    assert_eq!(state_keys(&connection), before);
    assert_eq!(
        turn_stops(&connection),
        vec!["{\"session_id\": \"idle\", \"discarded_pending_permissions\": 0}"]
    );
}

#[test]
fn a_stop_over_an_index_signed_under_another_key_is_left_to_the_daemon() {
    let (lane, connection) = keyed_lane("stop-foreign");
    record_notice(
        &lane,
        &[9; 32],
        "synthetic:0909090909090909",
        "rotated",
        notice("rotated", "tool_call"),
    );
    let before = state_keys(&connection);
    assert_eq!(
        deferred(&run_as(
            &lane,
            "claude-code",
            Some(HOME),
            stop(json!("rotated"))
        )),
        "direct_hook_permission_notice"
    );
    assert_eq!(state_keys(&connection), before);
    assert_eq!(turn_stops(&connection), Vec::<String>::new());
}

#[test]
fn a_stop_whose_session_python_may_spell_differently_is_left_to_the_daemon() {
    let (lane, connection) = keyed_lane("stop-number");
    for session in [json!(1.0), json!(["synthetic"]), json!({ "id": 1 })] {
        assert_eq!(
            deferred(&run_as(&lane, "claude-code", Some(HOME), stop(session))),
            "direct_hook_payload_unsupported"
        );
    }
    assert_eq!(turn_stops(&connection), Vec::<String>::new());
}
