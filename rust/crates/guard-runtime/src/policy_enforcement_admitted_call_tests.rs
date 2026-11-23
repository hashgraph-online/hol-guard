//! A call the user approved keeps its approval through `PostToolUse`, and
//! Guard's own approval wait on the hook's Guard home is not a subprocess to
//! review.

use super::*;
use crate::policy_enforcement::post::PostAdmission;

/// The user's approval on this exact call, with no inspection proof.
fn approved(approved: bool) -> PostAdmission {
    PostAdmission {
        approved,
        inspection: false,
    }
}

fn subprocess_review() -> PolicySnapshotV3 {
    let mut reviewed = policy("allow");
    reviewed.subprocess_action = "review".into();
    snapshot(reviewed)
}

fn approved_ls_output() -> NativeHookRequestV1 {
    let mut request = post_request(json!({
        "tool_call_id": "call-1",
        "tool_name": "bash",
        "tool_input": {"command": "ls -la"},
        "tool_response": "total 0"
    }));
    request.harness = "omp".into();
    request
}

fn clean_scan() -> HookReviewResponseV1 {
    let mut response = HookReviewResponseV1::allow("output_scan_allow");
    response.model_output_action = "allow_original".into();
    response.reviewed_output_sha256 =
        guard_hook_core::canonical_observed_output_sha256(&approved_ls_output().payload);
    assert!(response.reviewed_output_sha256.is_some());
    response
}

fn post(
    snapshot: &PolicySnapshotV3,
    response: HookReviewResponseV1,
    admitted: bool,
) -> HookReviewResponseV1 {
    crate::policy_enforcement::apply_post_tool_policy_with_witness(
        &AdmittedPolicySnapshot::new(snapshot.clone()).unwrap(),
        &approved_ls_output(),
        GuardHookPayloadKindV2::Inline,
        response,
        None,
        || approved(admitted),
        false,
    )
    .unwrap()
}

#[test]
fn approved_call_output_is_not_held_again_by_the_subprocess_floor() {
    let unapproved = post(&subprocess_review(), clean_scan(), false);
    assert_eq!(unapproved.decision, "deny");
    assert_eq!(unapproved.reason_code, "native_policy_review_required");

    let approved = post(&subprocess_review(), clean_scan(), true);
    assert_eq!(approved.decision, "allow");
}

#[test]
fn approval_witness_is_only_read_when_a_floor_would_hold_the_output() {
    let quiet = post(&snapshot(policy("allow")), clean_scan(), false);
    assert_eq!(quiet.decision, "allow");
    let read = std::cell::Cell::new(false);
    crate::policy_enforcement::apply_post_tool_policy_with_witness(
        &AdmittedPolicySnapshot::new(snapshot(policy("allow"))).unwrap(),
        &approved_ls_output(),
        GuardHookPayloadKindV2::Inline,
        clean_scan(),
        None,
        || {
            read.set(true);
            approved(true)
        },
        false,
    )
    .unwrap();
    assert!(!read.get());
}

#[test]
fn approval_witness_never_releases_secret_output_or_a_block_floor() {
    for code in [
        "output_secret_match",
        "source_secret_match",
        "sensitive_path",
    ] {
        let held = post(
            &subprocess_review(),
            HookReviewResponseV1::deny(code, "blocked"),
            true,
        );
        assert_eq!(held.decision, "deny", "{code}");
        assert_eq!(held.reason_code, code);
    }
    let mut blocked = policy("allow");
    blocked.subprocess_action = "block".into();
    let held = post(&snapshot(blocked), clean_scan(), true);
    assert_eq!(held.decision, "deny");
}

fn inspection_review() -> PreToolResultV1 {
    let mut result = generic_result("review");
    result.reason_code = "native_command_review_required".into();
    result
}

#[test]
fn own_approval_wait_passes_the_subprocess_floor() {
    let admitted = AdmittedPolicySnapshot::new(subprocess_review()).unwrap();
    let held = crate::policy_enforcement::apply_pre_tool_policy_with_inspection(
        &admitted,
        &json!({}),
        inspection_review(),
        false,
        None,
    )
    .unwrap();
    assert_eq!(held.decision, "deny");

    let passed = crate::policy_enforcement::apply_pre_tool_policy_with_inspection(
        &admitted,
        &json!({}),
        inspection_review(),
        true,
        None,
    )
    .unwrap();
    assert_eq!(passed.decision, "allow");
    assert_eq!(passed.reason_code, "native_exact_safe_command");
}

#[test]
fn own_approval_wait_keeps_other_reviews_and_sensitive_targets() {
    let admitted = AdmittedPolicySnapshot::new(subprocess_review()).unwrap();
    let mut other = generic_result("review");
    other.reason_code = "native_destructive_command".into();
    let held = crate::policy_enforcement::apply_pre_tool_policy_with_inspection(
        &admitted,
        &json!({}),
        other,
        true,
        None,
    )
    .unwrap();
    assert_eq!(held.decision, "deny");
    assert_eq!(held.reason_code, "native_destructive_command");

    let mut sensitive = inspection_review();
    sensitive.action.sensitive_target = true;
    let held = crate::policy_enforcement::apply_pre_tool_policy_with_inspection(
        &admitted,
        &json!({}),
        sensitive,
        true,
        None,
    )
    .unwrap();
    assert_eq!(held.decision, "deny");
}

#[test]
fn guard_home_must_match_for_the_inspection_witness() {
    let payload = |command: &str| json!({"tool_name": "bash", "tool_input": {"command": command}});
    let home = "/home/test/fixture/guard-home";
    assert!(crate::policy_enforcement::guard_approval_inspection(
        &payload("hol-guard approvals wait abc123 --json --home /home/test/fixture/guard-home"),
        home,
        Some("/home/test/fixture"),
    ));
    assert!(!crate::policy_enforcement::guard_approval_inspection(
        &payload("hol-guard approvals wait abc123 --json --home /home/test/other"),
        home,
        Some("/home/test/fixture"),
    ));
    assert!(!crate::policy_enforcement::guard_approval_inspection(
        &payload("hol-guard approvals approve abc123 --home /home/test/fixture/guard-home"),
        home,
        Some("/home/test/fixture"),
    ));
    assert!(!crate::policy_enforcement::guard_approval_inspection(
        &payload("hol-guard approvals wait abc123 --home /home/test/fixture/guard-home; rm -rf x"),
        home,
        Some("/home/test/fixture"),
    ));
}

fn post_with(
    snapshot: &PolicySnapshotV3,
    request: &NativeHookRequestV1,
    admitted: PostAdmission,
) -> HookReviewResponseV1 {
    let mut response = HookReviewResponseV1::allow("output_scan_allow");
    response.model_output_action = "allow_original".into();
    response.reviewed_output_sha256 =
        guard_hook_core::canonical_observed_output_sha256(&request.payload);
    crate::policy_enforcement::apply_post_tool_policy_with_witness(
        &AdmittedPolicySnapshot::new(snapshot.clone()).unwrap(),
        request,
        GuardHookPayloadKindV2::Inline,
        response,
        None,
        || admitted,
        false,
    )
    .unwrap()
}

fn post_for(request: &NativeHookRequestV1, admitted: PostAdmission) -> HookReviewResponseV1 {
    post_with(&subprocess_review(), request, admitted)
}

#[test]
fn approved_call_shell_result_object_is_released_but_an_excerpt_is_not() {
    let mut request = approved_ls_output();
    request.payload["tool_response"] = json!({"stdout": "total 0", "exit_code": 0});
    assert_eq!(post_for(&request, approved(false)).decision, "deny");
    assert_eq!(post_for(&request, approved(true)).decision, "allow");

    request.payload["tool_response_summary"] = json!({"output_sha256": "ab".repeat(32)});
    assert_eq!(post_for(&request, approved(true)).decision, "deny");
}

#[test]
fn own_approval_wait_result_is_not_held_by_the_subprocess_floor() {
    let mut request = post_request(json!({
        "tool_call_id": "call-wait",
        "tool_name": "bash",
        "tool_input": {
            "command": "hol-guard approvals wait abc123 --json --home /home/test/fixture/guard-home"
        },
        "tool_response": "{\"resolved\": true}"
    }));
    request.harness = "omp".into();
    request.guard_home = "/home/test/fixture/guard-home".into();
    request.cwd = Some("/home/test/fixture".into());
    assert!(crate::policy_enforcement::post::own_approval_wait(&request));
    let passed = post_for(
        &request,
        PostAdmission {
            approved: false,
            inspection: crate::policy_enforcement::post::own_approval_wait(&request),
        },
    );
    assert_eq!(passed.decision, "allow");

    request.guard_home = "/home/test/other".into();
    assert!(!crate::policy_enforcement::post::own_approval_wait(
        &request
    ));
}

#[test]
fn approved_file_read_is_released_only_on_guards_own_full_source_scan() {
    let mut reviewed = policy("allow");
    reviewed.default_action = "review".into();
    let admitted = AdmittedPolicySnapshot::new(snapshot(reviewed)).unwrap();
    let mut request = post_request(json!({
        "tool_call_id": "call-read",
        "tool_name": "read",
        "tool_input": {"path": "/home/test/fixture/README.md"},
        "guard_source_ref": {"output_sha256": "ab".repeat(32)}
    }));
    request.harness = "omp".into();
    let read = |reason: &str, admitted_call: bool| {
        let mut response = HookReviewResponseV1::allow(reason);
        response.model_output_action = "allow_original".into();
        response.reviewed_output_sha256 = Some("ab".repeat(32));
        crate::policy_enforcement::apply_post_tool_policy_with_witness(
            &admitted,
            &request,
            GuardHookPayloadKindV2::SourceFileRef,
            response,
            None,
            || approved(admitted_call),
            false,
        )
        .unwrap()
    };
    assert_eq!(read("source_full_scan_allow", false).decision, "deny");
    assert_eq!(read("source_full_scan_allow", true).decision, "allow");
    assert_eq!(read("output_scan_allow", true).decision, "deny");
}

/// Guard's own approval wait is still a command, so a configured execution
/// review applies to it. The inspection proof alone does not clear that
/// review, and the user's approval on the same call does.
#[test]
fn an_approved_inspection_call_clears_the_execution_review_floor() {
    let mut reviewed = policy("allow");
    reviewed
        .risk_actions
        .insert("execution".into(), "review".into());
    let execution_review = snapshot(reviewed);

    let mut request = post_request(json!({
        "tool_call_id": "call-wait",
        "tool_name": "bash",
        "tool_input": {
            "command": "hol-guard approvals wait abc123 --json --home /home/test/fixture/guard-home"
        },
        "tool_response": "{\"resolved\": true}"
    }));
    request.harness = "omp".into();
    request.guard_home = "/home/test/fixture/guard-home".into();
    request.cwd = Some("/home/test/fixture".into());
    assert!(crate::policy_enforcement::post::own_approval_wait(&request));

    let inspection_only = post_with(
        &execution_review,
        &request,
        PostAdmission {
            approved: false,
            inspection: true,
        },
    );
    assert_eq!(inspection_only.decision, "deny");
    assert_eq!(inspection_only.reason_code, "native_policy_review_required");

    let user_approved = post_with(
        &execution_review,
        &request,
        PostAdmission {
            approved: true,
            inspection: true,
        },
    );
    assert_eq!(user_approved.decision, "allow");
}

fn guide_home(label: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!("guard-guide-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".hol-support")).unwrap();
    std::fs::write(home.join(".hol-support/SAFETY.md"), "Read before acting.\n").unwrap();
    home
}

fn command_envelope(home: &std::path::Path, command: &str) -> guard_contracts::GuardHookEnvelopeV2 {
    let home = home.to_string_lossy().into_owned();
    guard_contracts::GuardHookEnvelopeV2 {
        schema: guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: Some("guide-test".into()),
        harness: "codex".into(),
        event: "PreToolUse".into(),
        raw_payload: json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        deadline_budget_ms: Some(1000),
        policy_generation: 1,
        policy_snapshot: json!({}),
        source: guard_contracts::GuardHookSourceMetadataV2 {
            cwd: Some(home.clone()),
            home_dir: home.clone(),
            guard_home: format!("{home}/.hol-guard"),
            source_ref_external_allowed: false,
            execution_environment: None,
        },
        recording_only: false,
        local_cli_rules: None,
        observe_local_cli: false,
        record_receipt: false,
        record_activity: false,
        record_pre_tool_activity: false,
        structured_output_config: None,
        containment_sink: None,
    }
}

#[test]
fn guards_own_safety_guide_read_passes_the_subprocess_floor() {
    let home = guide_home("pre");
    let admitted = AdmittedPolicySnapshot::new(subprocess_review()).unwrap();
    let pre = |command: &str, result: PreToolResultV1| {
        crate::policy_enforcement::apply_pre_tool_policy_for_hook(
            &admitted,
            &command_envelope(&home, command),
            result,
        )
        .unwrap()
    };

    let guide = pre("cat ~/.hol-support/SAFETY.md", generic_result("allow"));
    assert_eq!(guide.decision, "allow");

    // Another file, and the guide chained with anything else, keep the floor.
    let other = pre("cat ~/notes.md", generic_result("allow"));
    assert_eq!(other.decision, "deny");
    let chained = pre(
        "cat ~/.hol-support/SAFETY.md && ls",
        generic_result("allow"),
    );
    assert_eq!(chained.decision, "deny");

    // The guide never turns a native review into an allow, and a sensitive
    // target keeps the floor.
    let mut reviewed = generic_result("review");
    reviewed.reason_code = "native_command_review_required".into();
    assert_eq!(
        pre("cat ~/.hol-support/SAFETY.md", reviewed).decision,
        "deny"
    );
    let mut sensitive = generic_result("allow");
    sensitive.action.sensitive_target = true;
    assert_eq!(
        pre("cat ~/.hol-support/SAFETY.md", sensitive).decision,
        "deny"
    );
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn guards_own_safety_guide_output_is_not_held_by_the_subprocess_floor() {
    let home = guide_home("post");
    let mut request = post_request(json!({
        "tool_use_id": "call-guide",
        "tool_name": "Bash",
        "tool_input": {"command": "cat ~/.hol-support/SAFETY.md"},
        "tool_response": "Read before acting."
    }));
    request.harness = "codex".into();
    request.home_dir = home.to_string_lossy().into_owned();
    assert!(crate::policy_enforcement::post::own_approval_wait(&request));
    let passed = post_for(
        &request,
        PostAdmission {
            approved: false,
            inspection: crate::policy_enforcement::post::own_approval_wait(&request),
        },
    );
    assert_eq!(passed.decision, "allow");

    request.payload["tool_input"]["command"] = json!("cat ~/notes.md");
    assert!(!crate::policy_enforcement::post::own_approval_wait(
        &request
    ));
    request.payload["tool_input"]["command"] = json!("cat ~/.hol-support/SAFETY.md");
    request.home_dir = "/home/test/other".into();
    assert!(!crate::policy_enforcement::post::own_approval_wait(
        &request
    ));
    let _ = std::fs::remove_dir_all(home);
}
