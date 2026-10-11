use super::*;

const VECTORS: &str = include_str!("../testdata/hook_response_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn str_of<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key].as_str().unwrap_or_default()
}

fn obj(value: &Value) -> Object {
    value.as_object().cloned().unwrap_or_default()
}

fn check(category: &str, mut render: impl FnMut(&Value) -> Object) {
    let vectors = vectors();
    let cases = vectors[category].as_array().expect("category present");
    assert!(!cases.is_empty(), "{category} has vectors");
    for case in cases {
        let rendered = Value::Object(render(case));
        assert_eq!(rendered, case["expected"], "{category}: {case}");
    }
}

#[test]
fn pre_tool_matches_recorded_vectors() {
    check("pre_tool", |case| {
        pre_tool(str_of(case, "harness"), &obj(&case["response"]))
    });
}

#[test]
fn review_matches_recorded_vectors() {
    check("pre_tool_review", |case| {
        let approval = case["approval"].as_object();
        pre_tool_review(
            str_of(case, "harness"),
            &obj(&case["response"]),
            approval,
            case["linked_reason"].as_str(),
        )
    });
}

#[test]
fn prompt_matches_recorded_vectors() {
    check("prompt", |case| {
        prompt(str_of(case, "harness"), &obj(&case["response"]))
    });
}

#[test]
fn post_tool_matches_recorded_vectors() {
    check("post_tool", |case| {
        post_tool(str_of(case, "harness"), &obj(&case["response"]))
    });
}

#[test]
fn post_tool_block_matches_recorded_vectors() {
    check("post_tool_native_block", |case| {
        post_tool_block(
            case["reason"].as_str().unwrap_or(POST_BLOCK_REASON),
            case["reason_code"].as_str().unwrap_or("fast_path_block"),
        )
    });
}

#[test]
fn lifecycle_matches_recorded_vectors() {
    check("observe_lifecycle", |case| {
        observe_lifecycle(
            &canonical_hook_harness(str_of(case, "harness")),
            str_of(case, "event"),
            str_of(case, "reason_code"),
        )
    });
}

#[test]
fn recording_only_pre_tool_matches_recorded_vectors() {
    check("recording_only_pre_tool", |case| {
        recording_only_pre_tool(
            str_of(case, "harness"),
            str_of(case, "reason_code"),
            str_of(case, "reason"),
        )
    });
}

#[test]
fn edge_dispatch_routes_each_event_and_watch_posture() {
    let allow = json!({
        "decision": "allow", "minimum_action": "allow", "reason_code": "ok", "reason": "fine",
    });
    let review = json!({
        "decision": "deny", "minimum_action": "review", "reason_code": "rc", "reason": "pause",
    });
    let render = |event: &str, result: &Value, watch: bool| {
        Value::Object(render_edge_response("codex", event, result, watch).expect("rendered"))
    };
    assert_eq!(
        render("PreToolUse", &allow, true)["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
    assert_eq!(
        render("PreToolUse", &review, false)["policy_action"],
        "block"
    );
    let watched = render("PreToolUse", &review, true);
    assert_eq!(watched["policy_action"], "warn");
    assert_eq!(watched["hookSpecificOutput"]["permissionDecision"], "allow");
    assert_eq!(
        render("UserPromptSubmit", &review, true)["reason_code"],
        "watch_recording_only"
    );
    assert_eq!(
        render("UserPromptSubmit", &review, false)["decision"],
        "block"
    );
    assert!(render_edge_response("codex", "SessionStart", &allow, false).is_none());
    assert!(render_edge_response("codex", "PreToolUse", &json!("x"), false).is_none());
}
