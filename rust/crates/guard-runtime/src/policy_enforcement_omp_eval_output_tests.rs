use super::*;

#[test]
fn yield_report_output_preserves_intrinsic_and_installed_blocks() {
    let mut request = post_request(json!({
        "tool_name":"yield", "tool_input":{"type":"result", "data":{"summary":"Read complete", "report":"synthetic reference", "files":[]}},
        "tool_response":{"content":[{"type":"text", "text":"synthetic reference"}]}
    }));
    request.harness = "omp".into();
    assert_eq!(
        super::super::eval_output::bounded_output_action(&request),
        Some(PreToolActionTypeV1::Harness)
    );
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("execution".into(), "block".into());
    let result = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        guard_hook_core::review_post_tool(&request),
    )
    .unwrap();
    assert_eq!(result.decision, "allow", "{}", result.reason_code);
    for floor in ["intrinsic", "default", "harness"] {
        let mut blocked = effective.clone();
        if floor == "default" {
            blocked.default_action = "block".into();
        }
        if floor == "harness" {
            blocked.harness_actions.insert("omp".into(), "block".into());
        }
        let scanned = if floor == "intrinsic" {
            HookReviewResponseV1::deny("source_secret_match", "sensitive output")
        } else {
            HookReviewResponseV1::allow("output_scan_allow")
        };
        let result = apply_post_tool_policy(
            &snapshot(blocked),
            &request,
            GuardHookPayloadKindV2::Inline,
            scanned,
        )
        .unwrap();
        assert_eq!(result.decision, "deny", "{floor}");
    }
    request.payload["tool_input"]["data"]["command"] = json!("extra operation");
    assert!(super::super::eval_output::bounded_output_action(&request).is_none());
}

#[test]
fn read_only_eval_output_preserves_scans_and_installed_policy_floors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/omp-eval-output-tests")
        .join(format!("home-{}", std::process::id()));
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    std::fs::write(project.join("README.md"), "synthetic reference\n").unwrap();
    let mut request = post_request(json!({
        "tool_name":"eval", "tool_input":{"language":"js","code":"display(await read('README.md'))"},
        "tool_response":"synthetic reference\n"
    }));
    request.harness = "omp".into();
    request.home_dir = root.to_str().unwrap().into();
    request.cwd = Some(project.to_str().unwrap().into());
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("execution".into(), "block".into());
    let scanned = guard_hook_core::review_post_tool(&request);
    assert_eq!(scanned.reason_code, "output_scan_allow");
    let result = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        scanned,
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    for reason in ["native_output_subprocess_review", "source_secret_match"] {
        let scanned = if reason == "source_secret_match" {
            HookReviewResponseV1::deny(reason, "sensitive output")
        } else {
            HookReviewResponseV1::allow(reason)
        };
        let result = apply_post_tool_policy(
            &snapshot(effective.clone()),
            &request,
            GuardHookPayloadKindV2::Inline,
            scanned,
        )
        .unwrap();
        assert_eq!(result.decision, "deny", "{reason}");
    }
    for denied_policy in ["default", "harness"] {
        let mut denied = effective.clone();
        if denied_policy == "default" {
            denied.default_action = "block".into();
        } else {
            denied.harness_actions.insert("omp".into(), "block".into());
        }
        let result = apply_post_tool_policy(
            &snapshot(denied),
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap();
        assert_eq!(result.decision, "deny", "{denied_policy}");
    }
    for code in [
        "await tool.bash({command:'cat README.md'})",
        "await read(path)",
        "await writeFile('x','data')",
    ] {
        let mut unsafe_request = request.clone();
        unsafe_request.payload["tool_input"]["code"] = json!(code);
        assert!(super::super::eval_output::bounded_output_action(&unsafe_request).is_none());
    }
    request.harness = "codex".into();
    assert!(super::super::eval_output::bounded_output_action(&request).is_none());
    std::fs::remove_dir_all(root).unwrap();
}
