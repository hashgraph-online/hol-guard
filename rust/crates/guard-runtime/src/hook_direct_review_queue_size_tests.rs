use super::*;

#[test]
fn a_large_silent_reply_keeps_its_readable_wait_notification() {
    let home = store_home("review-queue-large-notification", SILENT_VECTORS);
    let guard_home = home.to_string_lossy().into_owned();
    let payload = Map::new();
    let mut binding = ask_binding();
    binding.review.blocked_request_mode = Some("safe-alternative".to_owned());
    let context = Context {
        harness: "claude-code",
        payload: &payload,
        recorded_payload: &payload,
        workspace: "/work/space",
        home_dir: "/home/user",
        guard_home: &guard_home,
        binding: &binding,
    };
    let mut result = json!({"reason_code": "native_review", "reason": "", "decision": "review"});
    let (mut low, mut high) = (0, HOOK_RENDER_MAX_BYTES);
    while low + 1 < high {
        let size = (low + high) / 2;
        result["reason"] = json!("x".repeat(size));
        let safe = safe_alternative_reason_with_retry(
            result["reason"].as_str().unwrap(),
            Some("native_review"),
            Some(true),
            true,
            false,
        );
        if silent_block("claude-code", result.as_object().unwrap(), &safe).is_some() {
            low = size;
        } else {
            high = size;
        }
    }
    result["reason"] = json!("x".repeat(low));
    let vectors: Value = serde_json::from_str(SILENT_VECTORS).unwrap();
    let response = silent(
        &context,
        result.as_object().unwrap(),
        "default",
        vectors["scenarios"][1]["request"].clone(),
        true,
        false,
    )
    .unwrap();
    assert!(response
        .to_string()
        .contains("hol-guard approvals wait r-new --json"));
    assert_eq!(response["approval_resume"]["request_id"], "r-new");
    std::fs::remove_dir_all(home).unwrap();
}
