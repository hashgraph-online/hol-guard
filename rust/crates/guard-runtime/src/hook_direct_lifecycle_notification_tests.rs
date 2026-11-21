//! Claude Code `Notification` hooks, answered as the daemon answers them.

use super::super::{deferred, lane, run_as, HOME};
use super::{keyed_lane, notice, pending, record_notice, BOUND_KEY, BOUND_KEY_ID};
use serde_json::{json, Value};

fn prompt(session: Value) -> Value {
    json!({
        "hook_event_name": "Notification",
        "notification_type": "permission_prompt",
        "session_id": session,
        "tool_name": "Bash",
    })
}

fn events(connection: &rusqlite::Connection) -> Vec<(String, Value)> {
    let mut statement = connection
        .prepare("select event_name, payload_json from guard_events order by rowid")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get::<_, String>(1)?)))
        .unwrap()
        .map(|row| {
            let (name, payload) = row.unwrap();
            (name, serde_json::from_str(&payload).unwrap())
        })
        .collect()
}

#[test]
fn a_claude_notification_that_is_not_a_permission_prompt_gets_the_constant() {
    let (lane, connection) = keyed_lane("notification-constant");
    let mut lowercase = prompt(json!("synthetic"));
    lowercase["hook_event_name"] = json!("notification");
    let mut listed = prompt(json!("synthetic"));
    listed["notification_type"] = json!(["permission_prompt"]);
    let mut idle = prompt(json!("synthetic"));
    idle["notification_type"] = json!("idle_prompt");
    for (payload, event) in [
        (json!({ "hook_event_name": "Notification" }), "Notification"),
        (idle, "Notification"),
        (listed, "Notification"),
        // `runtime_hook_event_name` keeps an unmapped name as sent.
        (lowercase, "notification"),
    ] {
        let result = run_as(&lane, "claude-code", Some(HOME), payload.clone());
        assert_eq!(
            result["edge"],
            json!({
                "harness_response": {
                    "continue": true,
                    "policy_action": "allow",
                    "reason_code": "native_hook_event_unavailable",
                    "hookSpecificOutput": { "hookEventName": event },
                }
            }),
            "{payload}"
        );
    }
    assert_eq!(events(&connection), vec![]);
}

#[test]
fn a_permission_prompt_without_a_notice_routes_to_guard_and_is_recorded() {
    // No notice row needs no key, so a binding without one answers too.
    let lane = lane("notification-no-notice", json!({}));
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table guard_events (
                 event_name text not null, payload_json text not null, occurred_at text not null
             );",
        )
        .unwrap();
    let mut sessionless = prompt(Value::Null);
    sessionless.as_object_mut().unwrap().remove("session_id");
    for payload in [prompt(json!("synthetic")), sessionless] {
        let result = run_as(&lane, "claude-code", Some(HOME), payload.clone());
        assert_eq!(result["outcome"], "answer", "{result}");
        let response = &result["edge"]["harness_response"];
        assert_eq!(
            response["hookSpecificOutput"]["hookEventName"],
            "Notification"
        );
        assert!(response["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .starts_with("HOL Guard intercepted the sensitive request"));
        assert!(response["systemMessage"]
            .as_str()
            .unwrap()
            .contains("attempt to use Bash"));
    }
    let recorded = events(&connection);
    assert_eq!(
        recorded,
        vec![
            (
                "claude/permission_prompt".to_owned(),
                json!({
                    "session_id": "synthetic",
                    "notification_type": "permission_prompt",
                    "tool_name": "Bash",
                    "notice": {},
                })
            ),
            (
                "claude/permission_prompt".to_owned(),
                json!({
                    "session_id": null,
                    "notification_type": "permission_prompt",
                    "tool_name": "Bash",
                    "notice": {},
                })
            ),
        ]
    );
    // The daemon's `json.dumps` key order and separators.
    let text: String = connection
        .query_row("select payload_json from guard_events limit 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        text,
        "{\"session_id\": \"synthetic\", \"notification_type\": \"permission_prompt\", \
         \"tool_name\": \"Bash\", \"notice\": {}}"
    );
}

#[test]
fn a_permission_prompt_with_a_notice_asks_the_guard_question_and_marks_it_seen() {
    let (lane, connection) = keyed_lane("notification-notice");
    record_notice(
        &lane,
        &BOUND_KEY,
        BOUND_KEY_ID,
        "tool",
        notice("tool", "tool_call"),
    );
    let result = run_as(&lane, "claude-code", Some(HOME), prompt(json!(" tool ")));
    assert_eq!(result["outcome"], "answer", "{result}");
    let context = result["edge"]["harness_response"]["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(context.contains("Call AskUserQuestion now"), "{context}");
    assert!(context.contains("Synthetic review reason."), "{context}");
    let seen = pending(&connection, "tool");
    assert_eq!(seen["permission_prompt_seen"], true, "{seen}");
    assert_eq!(seen["integrity"]["integrity_key_id"], BOUND_KEY_ID);
    let recorded = events(&connection);
    let (name, payload) = recorded.last().unwrap();
    assert_eq!(name, "claude/permission_prompt");
    assert_eq!(payload["session_id"], " tool ");
    assert_eq!(
        payload["notice"]["artifact_id"], "tool-artifact",
        "{payload}"
    );
}

#[test]
fn a_permission_prompt_the_resident_cannot_answer_alone_defers_untouched() {
    let (lane, connection) = keyed_lane("notification-defer");
    record_notice(
        &lane,
        &[9; 32],
        "synthetic:0909090909090909",
        "rotated",
        notice("rotated", "tool_call"),
    );
    record_notice(
        &lane,
        &BOUND_KEY,
        BOUND_KEY_ID,
        "busy",
        notice("busy", "tool_call"),
    );
    let claude =
        |payload: Value| deferred(&run_as(&lane, "claude-code", Some(HOME), payload)).to_owned();
    let baseline = events(&connection).len();
    // A row signed under another key is the daemon's to judge.
    assert_eq!(
        claude(prompt(json!("rotated"))),
        "direct_hook_permission_notice"
    );
    // A number is spelled as Python reads it, so the daemon records it.
    assert_eq!(claude(prompt(json!(7))), "direct_hook_payload_unsupported");
    let mut nested = prompt(json!("busy"));
    nested["tool_name"] = json!({ "name": "Bash" });
    assert_eq!(claude(nested), "direct_hook_payload_unsupported");
    // A held write lock leaves the hook to the daemon, which waits for it.
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        claude(prompt(json!("busy"))),
        "direct_hook_permission_notice"
    );
    connection.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        pending(&connection, "busy").get("permission_prompt_seen"),
        None
    );
    assert_eq!(
        pending(&connection, "rotated").get("permission_prompt_seen"),
        None
    );
    assert_eq!(events(&connection).len(), baseline);
}

#[test]
fn a_notice_without_the_bound_key_keeps_the_daemon_path() {
    let lane = lane("notification-unkeyed", json!({}));
    rusqlite::Connection::open(lane.fixture.root.join("guard.db"))
        .unwrap()
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
    assert_eq!(
        deferred(&run_as(
            &lane,
            "claude-code",
            Some(HOME),
            prompt(json!("unkeyed"))
        )),
        "direct_hook_permission_notice"
    );
}
