//! The Claude lifecycle ops against the sequences the daemon ran before them:
//! `claude_load_notice`, then `claude_mark_prompt_seen` for a notice, then
//! the event the daemon wrote itself and the copy it rendered. Every recorded
//! vector store, after every op step, is copied twice: one copy runs the old
//! sequence, the other the new op, and the response, the `sync_state` rows
//! and the audit events must match.

use std::collections::BTreeSet;
use std::path::Path;

use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::evaluate;
use super::session_ops::{agree, inputs, Base};
use super::vectors::{apply_raw, fresh_store, op_request, owned_rows, recorded_vectors};
use crate::guard_store_json::{dumps_default, py_strip};
use crate::hook_direct::claude_permission_text::{
    notification_tool_name, permission_prompt_event, permission_prompt_notification_response,
    permission_request_response, PERMISSION_PROMPT_EVENT,
};

const CLAUDE_NOTICE: &str = "claude_permission_notice:";

/// `_optional_string` on a notice field.
fn field(notice: &Map<String, Value>, name: &str) -> Option<String> {
    let text = py_strip(notice.get(name)?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

/// `_load_claude_permission_notice` and `_mark_claude_pending_permission_prompt_seen`
/// as two resident calls.
fn old_seen(base: &Base, at: &Path, session: &str, hook: &Map<String, Value>) -> Option<Value> {
    let notice = base.call(
        at,
        "claude_load_notice",
        json!({ "session_id": session, "tool_name": notification_tool_name(hook) }),
    )["notice"]
        .clone();
    let fields = notice.as_object()?;
    if let (Some(artifact_id), Some(artifact_hash), Some(command)) = (
        field(fields, "artifact_id"),
        field(fields, "artifact_hash"),
        field(fields, "command"),
    ) {
        base.call(
            at,
            "claude_mark_prompt_seen",
            json!({ "session_id": session, "artifact_id": artifact_id,
                    "artifact_hash": artifact_hash, "command": command }),
        );
    }
    Some(notice)
}

/// `store.add_event`, as the daemon wrote it after the resident calls.
fn old_event(base: &Base, at: &Path, name: &str, text: &str) {
    Connection::open(at)
        .expect("open")
        .execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
            params![name, text, base.request.now],
        )
        .expect("event");
}

fn notice_of(notice: &Option<Value>) -> Option<&Map<String, Value>> {
    notice.as_ref().and_then(Value::as_object)
}

/// The tools the store holds notices for, plus none and one it holds none for.
fn notice_tools(connection: &Connection) -> BTreeSet<Option<String>> {
    let mut tools = BTreeSet::from([None, Some("AbsentTool".to_owned())]);
    for (key, (payload, _)) in owned_rows(connection) {
        if key.starts_with(CLAUDE_NOTICE) {
            if let Some(tool) = payload.get("tool_name").and_then(Value::as_str) {
                tools.insert(Some(tool.to_owned()));
            }
        }
    }
    tools
}

/// The hook fields the daemon sends: the tool named directly, or only by the
/// notification's message.
fn hooks(session: &str, tool: Option<&str>) -> Vec<Map<String, Value>> {
    let mut direct = Map::new();
    direct.insert("session_id".into(), json!(session));
    direct.insert("notification_type".into(), json!("permission_prompt"));
    let mut by_message = direct.clone();
    if let Some(tool) = tool {
        direct.insert("tool_name".into(), json!(tool));
        by_message.insert(
            "message".into(),
            json!(format!("Claude needs your permission to use {tool}")),
        );
    }
    vec![direct, by_message]
}

#[test]
fn lifecycle_ops_match_the_sequences_they_replace() {
    let vectors = recorded_vectors();
    let key_b64 = vectors["key_b64"].as_str().expect("key").to_owned();
    let mut compared = 0;
    let mut answered_with_notice = 0;
    for scenario in vectors["scenarios"].as_array().expect("scenarios") {
        let name = scenario["name"].as_str().expect("name");
        let (path, connection) = fresh_store(&format!("claude-lifecycle-{name}"));
        for (step, action) in scenario["actions"]
            .as_array()
            .expect("actions")
            .iter()
            .enumerate()
        {
            if apply_raw(&connection, action) {
                continue;
            }
            let request = op_request(action, &path, &key_b64);
            evaluate(&request).unwrap_or_else(|code| panic!("{name} step {step}: {code}"));
            let base = Base { request: &request };
            let found = inputs(&connection);
            for session in &found.sessions {
                for tool in notice_tools(&connection) {
                    for hook in hooks(session, tool.as_deref()) {
                        let label = format!("{name} step {step}: {session} {tool:?} {hook:?}");
                        compared += 1;
                        let mut noticed = false;
                        agree(
                            &path,
                            &format!("{label} request"),
                            |at| {
                                let notice = old_seen(&base, at, session, &hook);
                                noticed = notice.is_some();
                                json!({ "harness_response":
                                    permission_request_response(&hook, notice_of(&notice)) })
                            },
                            |at| {
                                base.call(
                                    at,
                                    "claude_permission_request",
                                    json!({ "session_id": session, "payload": hook }),
                                )
                            },
                        );
                        answered_with_notice += usize::from(noticed);
                        agree(
                            &path,
                            &format!("{label} prompt"),
                            |at| {
                                let notice = old_seen(&base, at, session, &hook);
                                let event = permission_prompt_event(&hook, notice_of(&notice))
                                    .expect("event");
                                old_event(&base, at, PERMISSION_PROMPT_EVENT, &event);
                                json!({ "harness_response":
                                    permission_prompt_notification_response(&hook, notice_of(&notice)) })
                            },
                            |at| {
                                base.call(
                                    at,
                                    "claude_permission_prompt",
                                    json!({ "session_id": session, "payload": hook }),
                                )
                            },
                        );
                    }
                }
                agree(
                    &path,
                    &format!("{name} step {step}: stop {session}"),
                    |at| {
                        let discarded = base.old_discard(at, session);
                        let session_json = dumps_default(&json!(session)).expect("session");
                        old_event(
                            &base,
                            at,
                            "claude/turn_stop",
                            &format!(
                                "{{\"session_id\": {session_json}, \
                                 \"discarded_pending_permissions\": {discarded}}}"
                            ),
                        );
                        json!({ "discarded": discarded })
                    },
                    |at| {
                        base.call(
                            at,
                            "claude_turn_stop",
                            json!({ "session_id": session, "payload": { "session_id": session } }),
                        )
                    },
                );
            }
        }
        drop(connection);
        let _ = std::fs::remove_file(&path);
    }
    assert!(compared > 200, "only {compared} hooks compared");
    assert!(
        answered_with_notice > 10,
        "only {answered_with_notice} hooks found a notice"
    );
}

#[test]
fn a_hook_without_a_session_reads_no_notice_and_still_records_its_event() {
    let (path, connection) = fresh_store("claude-lifecycle-no-session");
    let request = guard_contracts::HookAuthorityStateRequestV1 {
        schema: guard_contracts::HOOK_AUTHORITY_STATE_REQUEST_SCHEMA.to_owned(),
        store_path: path.to_string_lossy().into_owned(),
        guard_home: std::env::temp_dir().to_string_lossy().into_owned(),
        now: "2026-10-28T00:00:00+00:00".to_owned(),
        ..Default::default()
    };
    let base = Base { request: &request };
    let hook = json!({ "notification_type": "permission_prompt", "tool_name": "Bash" });
    let answer = base.call(
        &path,
        "claude_permission_request",
        json!({ "payload": hook }),
    );
    assert_eq!(
        answer["harness_response"],
        permission_request_response(hook.as_object().expect("hook"), None)
    );
    base.call(
        &path,
        "claude_permission_prompt",
        json!({ "payload": hook }),
    );
    let stopped = base.call(&path, "claude_turn_stop", json!({ "payload": {} }));
    assert_eq!(stopped, json!({ "discarded": 0 }));
    let names: Vec<String> = super::vectors::events(&connection)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect();
    assert_eq!(names, ["claude/permission_prompt", "claude/turn_stop"]);
    drop(connection);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_lifecycle_op_without_its_hook_fields_is_refused() {
    let (path, connection) = fresh_store("claude-lifecycle-no-payload");
    for op in [
        "claude_permission_request",
        "claude_permission_prompt",
        "claude_turn_stop",
    ] {
        let request = guard_contracts::HookAuthorityStateRequestV1 {
            schema: guard_contracts::HOOK_AUTHORITY_STATE_REQUEST_SCHEMA.to_owned(),
            store_path: path.to_string_lossy().into_owned(),
            guard_home: std::env::temp_dir().to_string_lossy().into_owned(),
            op: op.to_owned(),
            now: "2026-10-28T00:00:00+00:00".to_owned(),
            session_id: Some("session".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            evaluate(&request),
            Err("native_hook_authority_state_invalid"),
            "{op}"
        );
    }
    assert!(super::vectors::events(&connection).is_empty());
    drop(connection);
    let _ = std::fs::remove_file(&path);
}

/// A session's pending review answers Claude's dialog by its kind: a tool
/// review denies the dialog in favour of the Guard approval question, and a
/// package review leaves the dialog to Claude with the review's reason.
#[test]
fn a_pending_review_answers_the_dialog_by_its_kind() {
    let vectors = recorded_vectors();
    let (path, connection) = fresh_store("claude-lifecycle-dialog");
    let request = guard_contracts::HookAuthorityStateRequestV1 {
        schema: guard_contracts::HOOK_AUTHORITY_STATE_REQUEST_SCHEMA.to_owned(),
        store_path: path.to_string_lossy().into_owned(),
        guard_home: std::env::temp_dir().to_string_lossy().into_owned(),
        now: "2026-10-28T00:00:00+00:00".to_owned(),
        integrity_key_b64: vectors["key_b64"].as_str().map(str::to_owned),
        integrity_key_id: Some("lifecycle-test-key".to_owned()),
        ..Default::default()
    };
    let base = Base { request: &request };
    let reason = "HOL Guard requires fresh approval for this command.";
    for (tool, artifact_type) in [("Bash", "tool_call"), ("npm", "package_request")] {
        base.call(
            &path,
            "claude_record_notice",
            json!({ "session_id": "session", "tool_name": tool, "payload": {
                "session_id": "session", "tool_name": tool, "artifact_id": format!("{tool}-artifact"),
                "artifact_hash": format!("{tool}-hash"), "command": format!("{tool} run"),
                "artifact_type": artifact_type, "reason": reason,
                "saved_at": "2026-10-28T00:00:00+00:00",
            } }),
        );
    }
    let dialog = |tool: &str| {
        base.call(
            &path,
            "claude_permission_request",
            json!({ "session_id": "session", "payload": { "session_id": "session", "tool_name": tool } }),
        )["harness_response"]
            .clone()
    };

    let tool_review = dialog("Bash");
    assert!(tool_review.get("guard_permission_passthrough").is_none());
    let decision = &tool_review["hookSpecificOutput"]["decision"];
    assert_eq!(decision["behavior"], "deny");
    assert_eq!(decision["interrupt"], false);
    assert!(decision["message"]
        .as_str()
        .is_some_and(|text| text.contains("AskUserQuestion")));

    let package_review = dialog("npm");
    assert_eq!(package_review["guard_permission_passthrough"], true);
    assert_eq!(
        package_review["hookSpecificOutput"],
        json!({ "hookEventName": "PermissionRequest" })
    );
    assert!(package_review["systemMessage"]
        .as_str()
        .is_some_and(|text| text.contains("requires fresh approval")));
    drop(connection);
    let _ = std::fs::remove_file(&path);
}
