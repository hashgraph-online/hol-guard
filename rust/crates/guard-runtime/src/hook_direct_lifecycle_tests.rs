use super::{deferred, drain, lane, run, run_as, HOME};
use serde_json::{json, Value};

fn lifecycle(name: &str) -> Value {
    json!({ "hook_event_name": name, "session_id": "synthetic" })
}

#[test]
fn a_claude_code_stop_is_answered_with_the_daemon_constant() {
    let lane = lane("lifecycle-stop", json!({}));
    let result = run_as(&lane, "claude-code", Some(HOME), lifecycle(" Stop "));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(
        result["edge"],
        json!({
            "harness_response": {
                "continue": true,
                "policy_action": "allow",
                "reason_code": "native_hook_event_unavailable",
                "hookSpecificOutput": { "hookEventName": "Stop" },
            }
        })
    );
    // The daemon records nothing for such a hook, and neither does the lane.
    assert_eq!(drain(&lane, None)["records"], json!([]));
}

#[test]
fn a_decision_harness_lifecycle_hook_gets_the_decision_constant() {
    let lane = lane("lifecycle-decision", json!({}));
    for harness in ["hermes", "openclaw"] {
        let result = run_as(&lane, harness, Some(HOME), lifecycle("SessionStart"));
        assert_eq!(
            result["edge"]["harness_response"],
            json!({
                "decision": "allow",
                "policy_action": "allow",
                "reason_code": "native_hook_event_unavailable",
            }),
            "{harness}: {result}"
        );
    }
    let grok = run_as(&lane, "grok", Some(HOME), lifecycle("SessionStart"));
    assert_eq!(grok["edge"]["harness_response"], json!({}), "{grok}");
    let kimi = run_as(&lane, "kimi", Some(HOME), lifecycle("SessionStart"));
    assert_eq!(
        kimi["edge"]["harness_response"]["hookSpecificOutput"]["hookEventName"],
        "SessionStart"
    );
}

#[test]
fn hooks_the_daemon_handles_itself_defer() {
    let lane = lane("lifecycle-daemon", json!({}));
    let unsupported = "direct_hook_event_unsupported";
    for name in [
        "copilotPermissionRequest",
        "beforeSubmitPrompt",
        "Session Start",
        "Stop\u{e9}",
    ] {
        assert_eq!(
            deferred(&run(&lane, lifecycle(name))),
            unsupported,
            "{name}"
        );
    }
    for name in ["PermissionRequest", "permission_request_v2"] {
        assert_eq!(
            deferred(&run_as(&lane, "kimi", Some(HOME), lifecycle(name))),
            unsupported,
            "{name}"
        );
    }
    let long = "x".repeat(65);
    assert_eq!(deferred(&run(&lane, lifecycle(&long))), unsupported);
    assert_eq!(run(&lane, lifecycle("Notification"))["outcome"], "answer");
    // The Cursor client renders its own lifecycle hooks.
    assert_eq!(
        deferred(&run_as(&lane, "cursor", Some(HOME), lifecycle("stop"))),
        unsupported
    );
    let mut probe = lifecycle("Stop");
    probe["guard_transition_probe"] = json!({});
    assert_eq!(deferred(&run(&lane, probe)), "direct_hook_transition_probe");
    let mut reference = lifecycle("Stop");
    reference["guard_source_ref"] = json!("ref");
    assert_eq!(
        deferred(&run(&lane, reference)),
        "direct_hook_payload_unsupported"
    );
}

#[test]
fn a_lifecycle_hook_for_an_app_guard_does_not_protect_defers() {
    let lane = lane("lifecycle-unmanaged", json!({}));
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table managed_installs (
                 harness text primary key, active integer not null, workspace text,
                 manifest_json text not null, updated_at text not null
             );
             insert into managed_installs values ('codex', 1, null, '{}', 'now');",
        )
        .unwrap();
    assert_eq!(run(&lane, lifecycle("Stop"))["outcome"], "answer");
    assert_eq!(
        deferred(&run_as(&lane, "claude-code", Some(HOME), lifecycle("Stop"))),
        "direct_hook_harness_unmanaged"
    );
}

fn permission_request(session: Value) -> Value {
    json!({ "hook_event_name": "PermissionRequest", "session_id": session, "tool_name": "Bash" })
}

#[test]
fn a_claude_permission_dialog_without_a_notice_is_left_to_claude() {
    let lane = lane("permission-passthrough", json!({}));
    let passthrough = json!({
        "harness_response": {
            "guard_permission_passthrough": true,
            "hookSpecificOutput": { "hookEventName": "PermissionRequest" },
        }
    });
    // A session without a notice, and payloads that name no session.
    for payload in [
        permission_request(json!("synthetic")),
        permission_request(json!("  ")),
        permission_request(json!(7)),
        json!({ "hookEventName": "permission_request_v2" }),
    ] {
        let result = run_as(&lane, "claude-code", Some(HOME), payload.clone());
        assert_eq!(result["outcome"], "answer", "{payload}: {result}");
        assert_eq!(result["edge"], passthrough, "{payload}");
    }
    assert_eq!(drain(&lane, None)["records"], json!([]));
    // A separator Python strips and Rust does not keeps the daemon path.
    assert_eq!(
        deferred(&run_as(
            &lane,
            "claude-code",
            Some(HOME),
            permission_request(json!("synthetic\u{1c}"))
        )),
        "direct_hook_event_unsupported"
    );
    // Harnesses without a passthrough keep the daemon path.
    assert_eq!(
        deferred(&run_as(
            &lane,
            "kimi",
            Some(HOME),
            permission_request(json!("synthetic"))
        )),
        "direct_hook_event_unsupported"
    );
}

#[test]
fn a_passthrough_permission_request_is_left_to_the_harness() {
    let lane = lane("permission-passthrough", json!({}));
    let passthrough = json!({
        "harness_response": {
            "hookSpecificOutput": { "hookEventName": "PermissionRequest" },
        }
    });
    for harness in ["codex", "copilot", "devin", "zcode"] {
        for payload in [
            permission_request(json!("synthetic")),
            json!({ "hookEventName": "permission_request_v2" }),
            json!({ "hookEventName": "permissionRequest" }),
        ] {
            let result = run_as(&lane, harness, Some(HOME), payload.clone());
            assert_eq!(result["outcome"], "answer", "{harness} {payload}: {result}");
            assert_eq!(result["edge"], passthrough, "{harness} {payload}");
        }
    }
    // The answer carries no decision and records nothing.
    assert_eq!(drain(&lane, None)["records"], json!([]));
}

#[test]
fn a_session_with_a_permission_notice_keeps_the_daemon_path() {
    let lane = lane("permission-notice", json!({}));
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table if not exists sync_state (
                 state_key text primary key, payload_json text not null, updated_at text not null
             );",
        )
        .unwrap();
    let claude = |session: &str| {
        run_as(
            &lane,
            "claude-code",
            Some(HOME),
            permission_request(json!(session)),
        )
    };
    for key in [
        "claude_permission_notice:synthetic",
        "claude_permission_notice:synthetic:Write",
        "claude_permission_notice:synthetic:",
    ] {
        connection
            .execute("insert into sync_state values (?1, '{}', 'now')", [key])
            .unwrap();
        // The daemon strips the session before it builds the key.
        assert_eq!(
            deferred(&claude(" synthetic ")),
            "direct_hook_permission_notice",
            "{key}"
        );
        connection
            .execute("delete from sync_state where state_key = ?1", [key])
            .unwrap();
    }
    // Notices of other sessions, including ones sharing a prefix, do not count.
    for key in [
        "claude_permission_notice:synthetic-2",
        "claude_permission_notice:synthetic2:Bash",
        "claude_permission_notice:synthetic;",
        "claude_permission_notice:other:Bash",
    ] {
        connection
            .execute("insert into sync_state values (?1, '{}', 'now')", [key])
            .unwrap();
    }
    assert_eq!(claude("synthetic")["outcome"], "answer");
}

const BOUND_KEY: [u8; 32] = [7; 32];
const BOUND_KEY_ID: &str = "synthetic:0707070707070707";

fn key_b64(key: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(key)
}

fn utc_now() -> String {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).unwrap(), "+00:00")
        .unwrap()
}

/// Records a notice the way the daemon does, signed under `key`.
fn record_notice(lane: &super::Lane, key: &[u8], key_id: &str, session: &str, notice: Value) {
    let root = lane.fixture.root.to_str().unwrap();
    let request: guard_contracts::HookAuthorityStateRequestV1 = serde_json::from_value(json!({
        "schema": guard_contracts::HOOK_AUTHORITY_STATE_REQUEST_SCHEMA,
        "store_path": format!("{root}/guard.db"),
        "guard_home": root,
        "op": "claude_record_notice",
        "now": utc_now(),
        "integrity_key_b64": key_b64(key),
        "integrity_key_id": key_id,
        "session_id": session,
        "tool_name": "Bash",
        "payload": notice,
    }))
    .unwrap();
    crate::hook_authority_state_op::evaluate(&request).unwrap();
}

fn keyed_lane(label: &str) -> (super::Lane, rusqlite::Connection) {
    let lane = lane(
        label,
        json!({ "integrity_key_b64": key_b64(&BOUND_KEY), "integrity_key_id": BOUND_KEY_ID }),
    );
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table if not exists sync_state (
                 state_key text primary key, payload_json text not null, updated_at text not null
             );
             create table if not exists guard_events (
                 event_name text not null, payload_json text not null, occurred_at text not null
             );",
        )
        .unwrap();
    (lane, connection)
}

fn notice(session: &str, artifact_type: &str) -> Value {
    json!({
        "session_id": session,
        "artifact_id": format!("{session}-artifact"),
        "artifact_hash": "synthetic-hash",
        "command": "npm install synthetic-package",
        "tool_name": "Bash",
        "artifact_type": artifact_type,
        "reason": "Synthetic review reason",
        // The daemon stamps every notice; a row without it reads as expired.
        "saved_at": utc_now(),
    })
}

fn pending(connection: &rusqlite::Connection, session: &str) -> Value {
    let payload: String = connection
        .query_row(
            "select payload_json from sync_state where state_key like ?1",
            [format!("claude_pending_permission:{session}:%")],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&payload).unwrap()
}

#[test]
fn a_notice_under_the_bound_key_is_answered_and_marked_seen() {
    let (lane, connection) = keyed_lane("permission-notice-keyed");
    record_notice(
        &lane,
        &BOUND_KEY,
        BOUND_KEY_ID,
        "package",
        notice("package", "package_request"),
    );
    record_notice(
        &lane,
        &BOUND_KEY,
        BOUND_KEY_ID,
        "tool",
        notice("tool", "tool_call"),
    );
    assert_eq!(
        pending(&connection, "package").get("permission_prompt_seen"),
        None
    );

    // A package request leaves the dialog to Claude and explains the review.
    let answered = run_as(
        &lane,
        "claude-code",
        Some(HOME),
        permission_request(json!(" package ")),
    );
    assert_eq!(answered["outcome"], "answer", "{answered}");
    let response = &answered["edge"]["harness_response"];
    assert_eq!(response["guard_permission_passthrough"], true, "{response}");
    assert_eq!(
        response["hookSpecificOutput"]["hookEventName"],
        "PermissionRequest"
    );
    assert!(response["systemMessage"].is_string(), "{response}");
    let seen = pending(&connection, "package");
    assert_eq!(seen["permission_prompt_seen"], true, "{seen}");
    assert!(seen["permission_prompt_seen_at"].is_string(), "{seen}");
    // The mark is signed under the bound key, so the daemon still accepts it.
    assert_eq!(seen["integrity"]["integrity_key_id"], BOUND_KEY_ID);

    // Any other artifact asks the user through Guard's question instead.
    let asked = run_as(
        &lane,
        "claude-code",
        Some(HOME),
        permission_request(json!("tool")),
    );
    assert_eq!(asked["outcome"], "answer", "{asked}");
    let decision = &asked["edge"]["harness_response"]["hookSpecificOutput"]["decision"];
    assert_eq!(decision["behavior"], "deny", "{asked}");
    assert_eq!(decision["interrupt"], false, "{asked}");
    assert_eq!(pending(&connection, "tool")["permission_prompt_seen"], true);
}

#[test]
fn a_notice_signed_under_another_key_is_left_to_the_daemon_untouched() {
    let (lane, connection) = keyed_lane("permission-notice-foreign");
    record_notice(
        &lane,
        &[9; 32],
        "synthetic:0909090909090909",
        "rotated",
        notice("rotated", "package_request"),
    );
    let rows = |connection: &rusqlite::Connection| -> Vec<(String, String)> {
        let mut statement = connection
            .prepare("select state_key, payload_json from sync_state order by state_key")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let before = rows(&connection);
    assert_eq!(
        deferred(&run_as(
            &lane,
            "claude-code",
            Some(HOME),
            permission_request(json!("rotated"))
        )),
        "direct_hook_permission_notice"
    );
    // Nothing was invalidated, marked or audited under the stale key.
    assert_eq!(rows(&connection), before);
    let events: i64 = connection
        .query_row("select count(*) from guard_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(events, 0);
}

#[test]
fn a_busy_store_leaves_the_notice_to_the_daemon() {
    let (lane, connection) = keyed_lane("permission-notice-busy");
    record_notice(
        &lane,
        &BOUND_KEY,
        BOUND_KEY_ID,
        "busy",
        notice("busy", "package_request"),
    );
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        deferred(&run_as(
            &lane,
            "claude-code",
            Some(HOME),
            permission_request(json!("busy"))
        )),
        "direct_hook_permission_notice"
    );
    connection.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        pending(&connection, "busy").get("permission_prompt_seen"),
        None
    );
}

#[path = "hook_direct_lifecycle_notification_tests.rs"]
mod notification;
