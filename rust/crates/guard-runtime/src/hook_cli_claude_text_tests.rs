use super::*;
use serde_json::json;

fn map(value: Value) -> Map<String, Value> {
    value.as_object().expect("object").clone()
}

fn copy(which: &str, payload: Value, notice: Option<Value>, reason: &str) -> String {
    let payload = map(payload);
    let notice = notice.map(map);
    claude_approval_copy(which, &payload, notice.as_ref(), reason)
        .expect("known name")
        .as_str()
        .expect("text")
        .to_owned()
}

#[test]
fn request_notices_name_the_tool_when_the_payload_does() {
    assert_eq!(
        copy(
            "permission_request_terminal_notice",
            json!({"tool_name": "  Bash  "}),
            None,
            "Reviewing this"
        ),
        "HOL Guard: reviewing Claude approval for Bash. Reviewing this."
    );
    assert_eq!(
        copy(
            "permission_request_terminal_notice",
            json!({}),
            None,
            "Reviewing this!"
        ),
        "HOL Guard: reviewing this Claude approval prompt. Reviewing this!"
    );
    assert!(copy(
        "permission_request_system_message",
        json!({"message": "Claude wants to use Edit"}),
        None,
        "Why"
    )
    .starts_with("HOL Guard is reviewing Claude's approval prompt for Edit."));
    assert!(copy(
        "permission_request_additional_context",
        json!({}),
        None,
        "Why"
    )
    .starts_with("This review came from HOL Guard, not from Claude alone. Why."));
}

#[test]
fn prompt_terminal_notice_covers_every_tool_and_reason_pairing() {
    let with_tool = json!({"tool_name": "Write"});
    assert!(copy(
        "permission_prompt_terminal_notice",
        with_tool.clone(),
        Some(json!({"reason": "Sensitive path"})),
        ""
    )
    .contains("for Write into a HOL Guard decision prompt. Sensitive path."));
    // A blank reason reads as absent, exactly as `_optional_string` does.
    assert_eq!(
        copy(
            "permission_prompt_terminal_notice",
            with_tool.clone(),
            Some(json!({"reason": "   "})),
            ""
        ),
        copy("permission_prompt_terminal_notice", with_tool, None, "")
    );
    assert!(
        copy("permission_prompt_terminal_notice", json!({}), None, "")
            .starts_with("HOL Guard is routing this Claude approval request into")
    );
}

#[test]
fn pretooluse_notice_names_the_tool_from_the_message() {
    assert!(copy(
        "native_pretooluse_terminal_notice",
        json!({"title": "Claude wants to use Bash"}),
        None,
        "Blocked"
    )
    .starts_with("HOL Guard intercepted Claude's attempt to use Bash. Blocked."));
    assert!(copy(
        "native_pretooluse_terminal_notice",
        json!({}),
        None,
        "Blocked"
    )
    .starts_with("HOL Guard intercepted a sensitive Claude action. Blocked."));
}

#[test]
fn ask_user_question_preference_follows_the_artifact_type() {
    let ask = |notice: Option<Value>| {
        let notice = notice.map(map);
        claude_approval_copy(
            "notice_prefers_ask_user_question",
            &Map::new(),
            notice.as_ref(),
            "",
        )
    };
    assert_eq!(
        ask(Some(json!({"artifact_type": "package_request"}))),
        Some(json!(false))
    );
    assert_eq!(
        ask(Some(json!({"artifact_type": "command"}))),
        Some(json!(true))
    );
    assert_eq!(ask(Some(json!({}))), Some(json!(true)));
    // No notice: the CLI never reaches the preference check without one.
    assert_eq!(ask(None), Some(json!(false)));
}

#[test]
fn an_unknown_name_has_no_copy() {
    assert!(claude_approval_copy("nope", &Map::new(), None, "").is_none());
}
