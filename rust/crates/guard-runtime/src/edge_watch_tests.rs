use super::*;
use guard_contracts::HookReviewResponseV1;

#[test]
fn harness_watch_releases_output_review_but_keeps_credentials_hidden() {
    use crate::policy_enforcement::tests::{policy, snapshot};
    let admitted = AdmittedPolicySnapshot::new(snapshot(policy("allow"))).unwrap();
    // A per-app Watch override arrives as `recording_only` on an enforce snapshot.
    let run = |payload: Value, recording_only: bool| -> Value {
        let mut watched = envelope("PostToolUse", payload);
        watched.harness = "omp".to_owned();
        watched.recording_only = recording_only;
        let guard_home = std::path::PathBuf::from(&watched.source.guard_home);
        let bytes = evaluate_envelope_with_snapshot(watched, &admitted);
        std::fs::remove_dir_all(guard_home).expect("remove edge generation fixture");
        serde_json::from_slice(&bytes.unwrap()).unwrap()
    };
    let notes = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "context_notes",
        "tool_input": {"text": "notes"},
        "tool_response": "Noted."
    });
    let protected = run(notes.clone(), false);
    assert_eq!(
        protected["result"]["reason_code"],
        "native_policy_review_required"
    );
    assert_eq!(protected["harness_response"]["decision"], "deny");
    let watched = run(notes, true);
    assert_eq!(watched["result"]["decision"], "allow");
    assert_eq!(watched["harness_response"]["decision"], "allow");
    assert_eq!(
        watched["harness_response"]["model_output_action"],
        "allow_original"
    );

    let token = format!("{}{}", ["gh", "p_"].concat(), "c".repeat(30));
    let credential = run(
        serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "cat config"},
            "tool_response": token
        }),
        true,
    );
    assert_eq!(credential["result"]["reason_code"], "output_secret_match");
    assert_eq!(credential["harness_response"]["decision"], "deny");
}

// `guard_rules::MAX_OUTPUT_CHARS`: past it the scanner reviews only an excerpt.
const MAX_OUTPUT_CHARS: usize = 5 * 1024 * 1024;

fn truncated_bash_output(prefix: &str) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        request_id: Some("edge-watch-test".to_owned()),
        harness: "omp".to_owned(),
        event_name: "PostToolUse".to_owned(),
        payload: serde_json::json!({
            "tool_name": "bash",
            "tool_input": {"command": "cat config"},
            "tool_response": format!("{prefix}{}", "x".repeat(MAX_OUTPUT_CHARS)),
        }),
        cwd: Some("/workspace".to_owned()),
        home_dir: "/home/test".to_owned(),
        guard_home: "/tmp/hol-guard-edge-watch-test".to_owned(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(5_000),
    }
}

fn watched_review(request: &NativeHookRequestV1) -> HookReviewResponseV1 {
    use crate::policy_enforcement::tests::{policy, snapshot};
    crate::policy_enforcement::apply_post_tool_policy_with_delivery(
        &AdmittedPolicySnapshot::new(snapshot(policy("allow"))).unwrap(),
        request,
        GuardHookPayloadKindV2::Inline,
        review_post_tool(request),
        None,
        true,
    )
    .unwrap()
}

#[test]
fn harness_watch_keeps_truncated_output_with_a_credential_hidden() {
    let token = format!("{}{}", ["gh", "p_"].concat(), "d".repeat(30));
    let watched = watched_review(&truncated_bash_output(&token));
    assert_eq!(watched.decision, "deny");
    assert_eq!(watched.reason_code, "output_too_large");
    assert_ne!(watched.model_output_action, "allow_original");
}

#[test]
fn harness_watch_keeps_the_reviewed_excerpt_of_a_clean_truncated_output() {
    // The scanner vouched for the excerpt only, so Watch never releases the
    // unscanned tail.
    let watched = watched_review(&truncated_bash_output("clean head "));
    assert_eq!(watched.decision, "allow");
    assert_eq!(watched.model_output_action, "replace_with_reviewed_excerpt");
}
