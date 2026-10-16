//! Vectors recorded from the Python helpers behind the daemon's Claude Code
//! `PermissionRequest` and permission prompt `Notification` replies
//! (`scripts/record_claude_permission_text_vectors.py`).

use serde_json::{Map, Value};

use super::{
    guard_approval_question_message, notice_prefers_ask_user_question,
    notification_tool_display_name, notification_tool_name, permission_prompt_additional_context,
    permission_prompt_event, permission_prompt_notification_response,
    permission_prompt_system_message, permission_request_reason, permission_request_response,
    permission_request_system_message, DEFAULT_REVIEW_REASON,
};

const VECTORS: &str = include_str!("../tests/fixtures/claude_permission_text_vectors.json");

fn optional_text(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

#[test]
fn matches_vectors_recorded_from_python() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 80, "{} vectors", vectors.len());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let payload: &Map<String, Value> = vector["payload"].as_object().unwrap();
        let notice: Option<&Map<String, Value>> = vector["notice"].as_object();
        let expected = &vector["expected"];
        assert_eq!(
            optional_text(notification_tool_name(payload)),
            expected["notification_tool_name"],
            "{name}: notification_tool_name"
        );
        assert_eq!(
            optional_text(notification_tool_display_name(payload)),
            expected["notification_tool_display_name"],
            "{name}: notification_tool_display_name"
        );
        assert_eq!(
            notice.map_or(Value::Null, |fields| Value::Bool(
                notice_prefers_ask_user_question(fields)
            )),
            expected["prefers_ask_user_question"],
            "{name}: prefers_ask_user_question"
        );
        assert_eq!(
            guard_approval_question_message(notice),
            expected["approval_question_message"].as_str().unwrap(),
            "{name}: approval_question_message"
        );
        assert_eq!(
            permission_prompt_system_message(payload, notice),
            expected["prompt_system_message"].as_str().unwrap(),
            "{name}: prompt_system_message"
        );
        let native_reason = notice.map_or_else(
            || DEFAULT_REVIEW_REASON.to_owned(),
            permission_request_reason,
        );
        assert_eq!(
            native_reason,
            expected["native_reason"].as_str().unwrap(),
            "{name}: native_reason"
        );
        assert_eq!(
            permission_request_system_message(payload, &native_reason),
            expected["request_system_message"].as_str().unwrap(),
            "{name}: request_system_message"
        );
        assert_eq!(
            permission_request_response(payload, notice),
            expected["response"],
            "{name}: response"
        );
        assert_eq!(
            permission_prompt_additional_context(notice),
            expected["prompt_additional_context"].as_str().unwrap(),
            "{name}: prompt_additional_context"
        );
        assert_eq!(
            permission_prompt_notification_response(payload, notice),
            expected["notification_response"],
            "{name}: notification_response"
        );
        assert_eq!(
            permission_prompt_event(payload, notice).as_deref(),
            expected["notification_event"].as_str(),
            "{name}: notification_event"
        );
    }
}
