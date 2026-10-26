use super::*;

#[test]
fn scanned_structured_edit_output_does_not_invent_a_persistence_review() {
    let request = post_request(json!({
        "tool_name": "Edit", "tool_input": {"file_path": "src/ordinary.ts"},
        "tool_response": {
            "originalFile": "export const value = 1;",
            "oldString": "value = 1", "newString": "value = 2",
            "structuredPatch": [{"lines": ["-value = 1", "+value = 2"]}]
        }
    }));
    let mut effective = policy("warn");
    effective
        .risk_actions
        .insert("persistence".into(), "require-reapproval".into());
    let native = guard_hook_core::review_post_tool(&request);
    assert_eq!(native.reason_code, "output_scan_allow");
    let result = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        native,
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    assert_eq!(result.policy_action.as_deref(), Some("warn"));
    effective.default_action = "block".into();
    let denied = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        guard_hook_core::review_post_tool(&request),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
}

#[test]
fn bounded_task_outputs_keep_input_proof_without_lowering_security_floors() {
    let payload = json!({
        "tool_name": "TodoWrite",
        "tool_input": {"todos": [{"content": "Validate tests", "status": "completed"}]},
        "tool_response": "Task list updated"
    });
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("execution".into(), "block".into());
    let result = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &post_request(payload.clone()),
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    assert_eq!(result.policy_action.as_deref(), Some("allow"));
    let output_risk = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &post_request(payload.clone()),
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("native_output_subprocess_review"),
    )
    .unwrap();
    assert_eq!(output_risk.decision, "deny");
    effective
        .harness_actions
        .insert("claude-code".into(), "block".into());
    let harness_denied = apply_post_tool_policy(
        &snapshot(effective),
        &post_request(payload.clone()),
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(harness_denied.decision, "deny");
    for tool in ["TodoWrite", "TaskOutput"] {
        let input = if tool == "TodoWrite" {
            json!({"todos": []})
        } else {
            json!({"task_id": "existing-task", "block": true, "timeout": 1000})
        };
        let request =
            post_request(json!({"tool_name": tool, "tool_input": input, "tool_response": "safe"}));
        let denied = apply_post_tool_policy(
            &snapshot(policy("allow")),
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::deny("source_secret_match", "output contains sensitive material"),
        )
        .unwrap();
        assert_eq!(denied.decision, "deny");
        let denied = apply_post_tool_policy(
            &snapshot(policy("block")),
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap();
        assert_eq!(denied.decision, "deny");
    }
    for other in [
        json!({"tool_name": "TodoWrite", "tool_input": {"todos": [], "command": "run something"}}),
        json!({"tool_name": "mcp__server__TodoWrite", "tool_input": {"todos": []}}),
        json!({"tool_name": "TodoWrite", "toolName": "TaskOutput", "tool_input": {"todos": []}}),
        json!({"tool_name": "TaskOutput", "tool_input": {"task_id": "../credentials"}}),
    ] {
        assert!(!guard_command::pretool::bounded_task_metadata_output(
            &other,
            "claude-code"
        ));
    }
}

#[test]
fn omp_delegation_acknowledgements_preserve_output_and_harness_floors() {
    let input = json!({
        "tool_name": "task",
        "tool_input": {"context": "Read-only lookup", "tasks": [{
            "name": "ReadmeSentence", "agent": "scout", "task": "Read README.md",
            "schemaMode": "permissive", "tools": []
        }]},
        "tool_response": {"content": [], "details": {"async": {"state": "running"}}}
    });
    let mut request = post_request(input.clone());
    request.harness = "omp".into();
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("execution".into(), "review".into());
    let output = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(output.decision, "allow");
    let denied = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::deny("source_secret_match", "sensitive output"),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
    effective
        .harness_actions
        .insert("omp".into(), "block".into());
    let denied = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
    assert!(!guard_command::pretool::bounded_task_metadata_output(
        &input, "codex"
    ));
    let mut unsafe_input = input;
    unsafe_input["tool_input"]["command"] = json!("run something");
    assert!(!guard_command::pretool::bounded_task_metadata_output(
        &unsafe_input,
        "omp"
    ));
}

#[test]
fn omp_learn_acknowledgement_is_released_without_lowering_output_floors() {
    // The OMP extension's tool_result payload shape.
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_call_id": "call-learn-1",
        "tool_name": "learn",
        "tool_input": {"memory": "Run the project tests with cargo test before pushing."},
        "tool_response": {"content": [{"type": "text", "text": "Memory saved."}]},
        "is_error": false
    });
    let mut request = post_request(input.clone());
    request.harness = "omp".into();
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("execution".into(), "review".into());
    let output = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(output.decision, "allow");
    let denied = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::deny("source_secret_match", "sensitive output"),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
    effective
        .harness_actions
        .insert("omp".into(), "block".into());
    let denied = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
    for harness in ["pi", "codex"] {
        assert!(!guard_command::pretool::bounded_task_metadata_output(
            &input, harness
        ));
    }
    // Oh My Pi sends the optional `context` beside the memory, and a note that
    // ran still has an acknowledgement to return.
    for tool_input in [
        json!({"memory": "note", "context": "Learned while fixing the shelf."}),
        json!({"memory": "note", "scope": "project"}),
        json!({"memory": "note", "context": concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyzA")}),
    ] {
        let mut changed = input.clone();
        changed["tool_input"] = tool_input.clone();
        assert!(
            guard_command::pretool::bounded_task_metadata_output(&changed, "omp"),
            "{tool_input}"
        );
    }
    for tool_input in [
        json!({"memory": "note", "scope": "global"}),
        json!({"memory": ["note"]}),
        json!({"memory": "  "}),
        json!({}),
        json!({"memory": "note", "command": "rm -rf build"}),
        json!({"memory": "note", "context": ["not", "a", "string"]}),
        json!({"context": "a context without a memory"}),
    ] {
        let mut changed = input.clone();
        changed["tool_input"] = tool_input.clone();
        assert!(
            !guard_command::pretool::bounded_task_metadata_output(&changed, "omp"),
            "{tool_input}"
        );
    }
}

#[test]
fn omp_learn_with_its_optional_context_is_released_too() {
    // Current Oh My Pi sends the schema's optional `context` with every lesson;
    // the approved call's acknowledgement must still reach the agent.
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_call_id": "call-learn-2",
        "tool_name": "learn",
        "tool_input": {
            "memory": "GitrueNAS/test: hello.py and jokes.py build again after the merge-marker fix.",
            "context": "Code review turn on ~/Documents/G/GitrueNAS/test; the earlier memory is stale"
        },
        "tool_response": {"content": [{"type": "text", "text": "Memory saved."}]},
        "is_error": false
    });
    assert!(guard_command::pretool::bounded_task_metadata_output(
        &input, "omp"
    ));
    let mut request = post_request(input);
    request.harness = "omp".into();
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("execution".into(), "review".into());
    let output = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(output.decision, "allow");
}

#[test]
fn omp_learn_that_also_writes_a_skill_is_released_too() {
    // Oh My Pi 18.11's `learn` can create or update a managed skill in the
    // same call. Its review ran before the write; the acknowledgement that
    // comes back afterwards has nothing left to approve.
    let input = json!({
        "hook_event_name": "PostToolUse",
        "tool_call_id": "call-learn-3",
        "tool_name": "learn",
        "tool_input": {
            "memory": "Run the test suite with python3 -m pytest from the repository root.",
            "context": "Code review turn",
            "skill": {
                "action": "create",
                "name": "repo-tests",
                "description": "How to run this repository's tests.",
                "body": "# Repo tests\n\nRun the suite from the repository root before pushing."
            }
        },
        "tool_response": {"content": [{"type": "text", "text": "Lesson stored. Created managed skill \"repo-tests\"."}]},
        "is_error": false
    });
    assert!(guard_command::pretool::bounded_task_metadata_output(
        &input, "omp"
    ));
    let mut request = post_request(input.clone());
    request.harness = "omp".into();
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("execution".into(), "review".into());
    let output = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(output.decision, "allow");
    // The returned content still meets its own scan.
    let denied = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::deny("source_secret_match", "sensitive output"),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
    let skill = &input["tool_input"]["skill"];
    let with = |key: &str, value: Value| {
        let mut changed = skill.clone();
        changed[key] = value;
        changed
    };
    let mut extra = skill.clone();
    extra["path"] = json!("../other-skill");
    let mut missing = skill.clone();
    missing.as_object_mut().unwrap().remove("body");
    for (case, tool_input) in [
        (
            "update",
            json!({"memory": "note", "skill": with("action", json!("update"))}),
        ),
        (
            "no context",
            json!({"memory": "note", "skill": skill.clone()}),
        ),
    ] {
        let mut changed = input.clone();
        changed["tool_input"] = tool_input;
        assert!(
            guard_command::pretool::bounded_task_metadata_output(&changed, "omp"),
            "{case}"
        );
    }
    for (case, tool_input) in [
        (
            "delete",
            json!({"memory": "note", "skill": with("action", json!("delete"))}),
        ),
        (
            "path name",
            json!({"memory": "note", "skill": with("name", json!("../repo-tests"))}),
        ),
        (
            "upper case",
            json!({"memory": "note", "skill": with("name", json!("Repo-Tests"))}),
        ),
        (
            "double hyphen",
            json!({"memory": "note", "skill": with("name", json!("repo--tests"))}),
        ),
        (
            "long name",
            json!({"memory": "note", "skill": with("name", json!("a".repeat(65)))}),
        ),
        (
            "body not text",
            json!({"memory": "note", "skill": with("body", json!(["text"]))}),
        ),
        (
            "extra key",
            json!({"memory": "note", "skill": extra.clone()}),
        ),
        (
            "missing body",
            json!({"memory": "note", "skill": missing.clone()}),
        ),
        (
            "not an object",
            json!({"memory": "note", "skill": "repo-tests"}),
        ),
        (
            "global",
            json!({"memory": "note", "scope": "global", "skill": skill.clone()}),
        ),
        ("skill alone", json!({"skill": skill.clone()})),
    ] {
        let mut changed = input.clone();
        changed["tool_input"] = tool_input;
        assert!(
            !guard_command::pretool::bounded_task_metadata_output(&changed, "omp"),
            "{case}"
        );
    }
}

#[test]
fn policy_allow_cannot_lower_intrinsic_review_or_block() {
    let snapshot = snapshot(policy("allow"));
    for action in ["review", "block"] {
        let result = apply_pre_tool_policy(
            &snapshot,
            &Value::Object(Map::new()),
            generic_result(action),
        )
        .unwrap();
        assert_eq!(result.minimum_action, action);
        assert_eq!(result.decision, "deny");
    }
}

#[test]
fn policy_block_raises_intrinsic_allow() {
    let snapshot = snapshot(policy("block"));
    let result = apply_pre_tool_policy(
        &snapshot,
        &Value::Object(Map::new()),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.reason_code, "native_policy_block");
}

#[test]
fn conflicting_harness_aliases_fail_closed() {
    let mut effective = policy("allow");
    effective
        .harness_actions
        .insert("claude".into(), "review".into());
    effective
        .harness_actions
        .insert("claude-code".into(), "block".into());
    let result = apply_pre_tool_policy(
        &snapshot(effective),
        &Value::Object(Map::new()),
        generic_result("allow"),
    );
    assert_eq!(
        result.unwrap_err(),
        "native_policy_harness_selector_conflict"
    );
}

#[test]
fn conflicting_harness_risk_aliases_fail_closed() {
    let mut effective = policy("allow");
    effective.harness_risk_actions.insert(
        "claude".into(),
        BTreeMap::from([(String::from("execution"), String::from("review"))]),
    );
    effective.harness_risk_actions.insert(
        "claude-code".into(),
        BTreeMap::from([(String::from("execution"), String::from("block"))]),
    );
    let result = apply_pre_tool_policy(
        &snapshot(effective),
        &Value::Object(Map::new()),
        generic_result("allow"),
    );
    assert_eq!(
        result.unwrap_err(),
        "native_policy_harness_selector_conflict"
    );
}

#[test]
fn post_intrinsic_block_cannot_be_lowered_by_allow_policy() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "safe-looking output"
    }));
    let response =
        HookReviewResponseV1::deny("source_secret_match", "native source content was blocked");
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        response,
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("block"));
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(!encoded.contains("safe-looking"));
}

#[test]
fn post_warning_policy_keeps_a_silent_warn_on_a_proven_allow() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "safe-looking output"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("warn")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    assert_eq!(result.policy_action.as_deref(), Some("warn"));
    assert_eq!(result.reason_code, "native_policy_warning");
    assert_eq!(result.notice, "none");
    assert_eq!(result.reason, None);
}

#[test]
fn scanned_write_output_does_not_invent_persistence_but_preserves_denials() {
    let request = post_request(json!({"tool_name": "write", "tool_response": "wrote source file"}));
    let mut effective = policy("warn");
    effective
        .risk_actions
        .insert("persistence".into(), "require-reapproval".into());
    let result = apply_post_tool_policy(
        &snapshot(effective.clone()),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    assert_eq!(result.policy_action.as_deref(), Some("warn"));
    effective.default_action = "block".into();
    let result = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::deny("sensitive_output", "synthetic protected content"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
}

#[test]
fn post_policy_fields_raise_without_python_semantic_input() {
    let mut effective = policy("allow");
    effective.unknown_publisher_action = "review".into();
    effective.changed_hash_action = "block".into();
    effective
        .publisher_actions
        .insert("trusted".into(), "allow".into());
    effective
        .artifact_actions
        .insert("pkg-a".into(), "block".into());
    let request = post_request(json!({
        "tool_name": "npm_install",
        "publisher": "trusted",
        "artifact_id": "pkg-a",
        "changed": true,
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("block"));
}

#[test]
fn unknown_post_action_is_review_even_when_default_allows() {
    let request = post_request(json!({
        "tool_name": "future_tool_v9",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("review"));
    assert_eq!(result.reason_code, "native_policy_review_required");
}

#[test]
fn unreadable_tool_remains_unknown_under_allow_policy() {
    let request = post_request(json!({
        "tool_name": "unreadable_tool",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("review"));
    assert_eq!(result.reason_code, "native_policy_review_required");
}

#[test]
fn conflicting_request_selectors_fail_closed() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "publisher": "one",
        "publisherId": "two",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    );
    assert_eq!(result.unwrap_err(), "native_policy_selector_conflict");
}

#[test]
fn observe_keeps_credential_block_but_does_not_enforce_policy_only_floor() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "ok"
    }));
    let mut observed_snapshot = snapshot(policy("block"));
    observed_snapshot.mode = "observe".into();
    let policy_only = apply_post_tool_policy(
        &observed_snapshot,
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(policy_only.decision, "allow");
    assert_eq!(policy_only.policy_action.as_deref(), Some("block"));

    // Watch records an intrinsic block that the model can safely read past.
    let intrinsic = apply_post_tool_policy(
        &observed_snapshot,
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::deny("output_mismatch", "blocked").observed(None),
    )
    .unwrap();
    assert_eq!(intrinsic.decision, "allow");
    assert_eq!(intrinsic.policy_action.as_deref(), Some("block"));
    assert_eq!(intrinsic.observed_policy_action.as_deref(), Some("block"));
    assert!(intrinsic.observe_mode);

    // It never hands output that may carry a credential to the model. The
    // edge reviews output with observe off, so the join sees the scanner's
    // own denial.
    for code in [
        "source_secret_match",
        "output_secret_match",
        "sensitive_path",
        "scanner_budget_exhausted",
        "output_too_large",
        "no_output_to_review",
    ] {
        let credential = apply_post_tool_policy(
            &observed_snapshot,
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::deny(code, "blocked"),
        )
        .unwrap();
        assert_eq!(credential.decision, "deny", "{code}");
        assert_eq!(credential.reason_code, code);
        assert_ne!(credential.model_output_action, "allow_original", "{code}");
    }
}

fn watched_post_tool(
    snapshot: &PolicySnapshotV3,
    request: &NativeHookRequestV1,
    response: HookReviewResponseV1,
    recording_only: bool,
) -> HookReviewResponseV1 {
    crate::policy_enforcement::apply_post_tool_policy_with_delivery(
        &AdmittedPolicySnapshot::new(snapshot.clone()).unwrap(),
        request,
        GuardHookPayloadKindV2::Inline,
        response,
        None,
        recording_only,
    )
    .unwrap()
}

#[test]
fn harness_watch_releases_an_unknown_tool_output_review() {
    // Oh My Pi's own Watch override leaves the snapshot in enforce mode.
    let mut request = post_request(json!({
        "tool_name": "context_notes",
        "tool_input": {"text": "notes"},
        "tool_response": "Noted."
    }));
    request.harness = "omp".into();
    let enforced = snapshot(policy("allow"));
    let protected = watched_post_tool(
        &enforced,
        &request,
        HookReviewResponseV1::allow("output_scan_allow"),
        false,
    );
    assert_eq!(protected.decision, "deny");
    assert_eq!(protected.reason_code, "native_policy_review_required");

    let watched = watched_post_tool(
        &enforced,
        &request,
        HookReviewResponseV1::allow("output_scan_allow"),
        true,
    );
    assert_eq!(watched.decision, "allow");
    assert_eq!(watched.model_output_action, "allow_original");
    assert_eq!(
        watched.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text("Noted.").as_str())
    );
}

#[test]
fn harness_watch_keeps_credential_output_from_the_model() {
    let mut request = post_request(json!({
        "tool_name": "bash",
        "tool_input": {"command": "cat config"},
        "tool_response": "redacted"
    }));
    request.harness = "omp".into();
    for code in [
        "output_secret_match",
        "source_secret_match",
        "sensitive_path",
    ] {
        let watched = watched_post_tool(
            &snapshot(policy("allow")),
            &request,
            HookReviewResponseV1::deny(code, "blocked"),
            true,
        );
        assert_eq!(watched.decision, "deny", "{code}");
        assert_eq!(watched.reason_code, code);
    }
}

fn observe_post_tool(payload: Value, response: HookReviewResponseV1) -> HookReviewResponseV1 {
    let mut observed_snapshot = snapshot(policy("allow"));
    observed_snapshot.mode = "observe".into();
    apply_post_tool_policy(
        &observed_snapshot,
        &post_request(payload),
        GuardHookPayloadKindV2::Inline,
        response,
    )
    .unwrap()
}

fn native_deny() -> HookReviewResponseV1 {
    // Watch keeps credential matches blocked, so these proofs use another
    // intrinsic denial.
    let mut response = HookReviewResponseV1::deny("output_mismatch", "output requires review");
    response.policy_action = Some("block".to_owned());
    response
}

#[test]
fn test_complete_inline_recording_only_output_gets_matching_proof() {
    let content = "complete tool output";
    let payload = json!({"tool_response": [{"type": "text", "text": content}]});

    let result = observe_post_tool(payload, native_deny());

    assert_eq!(result.decision, "allow");
    assert_eq!(result.model_output_action, "allow_original");
    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text(content).as_str())
    );
}

#[test]
fn test_source_ref_proof_is_copied_without_hashing_an_excerpt() {
    let digest = "a".repeat(64);
    let payload = json!({
        "guard_source_ref": {"output_sha256": digest},
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });

    let result = observe_post_tool(payload, native_deny());

    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(digest.as_str())
    );
}

#[test]
fn test_inherited_excerpt_digest_is_removed_during_allow_original_rewrite() {
    let payload = json!({
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });
    let mut native = native_deny();
    native.reviewed_output_sha256 = Some(guard_hook_core::sha256_text("bounded excerpt"));

    let result = observe_post_tool(payload, native);

    assert_eq!(result.decision, "allow");
    assert_eq!(result.model_output_action, "allow_original");
    assert!(result.reviewed_output_sha256.is_none());
}

#[test]
fn test_inherited_excerpt_digest_is_removed_from_existing_allow_response() {
    let payload = json!({
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });
    let mut native = HookReviewResponseV1::allow("output_scan_allow");
    native.policy_action = Some("warn".to_owned());
    native.reviewed_output_sha256 = Some(guard_hook_core::sha256_text("bounded excerpt"));

    let result = observe_post_tool(payload, native);

    assert_eq!(result.decision, "allow");
    assert_eq!(result.model_output_action, "allow_original");
    assert!(result.reviewed_output_sha256.is_none());
}

#[test]
fn test_stale_allow_original_uses_canonical_inline_proof() {
    let content = "canonical inline output";
    let mut native = HookReviewResponseV1::allow("output_scan_allow");
    native.policy_action = Some("warn".to_owned());
    native.reviewed_output_sha256 = Some("b".repeat(64));
    let payload = json!({"tool_response": [{"type": "text", "text": content}]});

    let result = observe_post_tool(payload, native);

    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text(content).as_str())
    );
}

#[test]
fn test_summary_without_digest_falls_back_to_complete_inline_output() {
    let content = "complete inline output";
    let payload = json!({
        "tool_response_summary": {"text_excerpt": "bounded excerpt"},
        "tool_response": [{"type": "text", "text": content}],
    });

    let result = observe_post_tool(payload, native_deny());

    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text(content).as_str())
    );
}

#[test]
fn test_truncated_or_excerpt_only_output_gets_no_fabricated_proof() {
    let payload = json!({
        "stdout": "bounded excerpt",
        "tool_response_summary": {
            "text_excerpt": "bounded excerpt",
            "excerpt_truncated": true,
        },
    });

    let result = observe_post_tool(payload, native_deny());

    assert!(result.reviewed_output_sha256.is_none());
    assert!(result.observe_mode);
}

#[test]
fn test_existing_observe_mode_is_preserved_during_rewrite() {
    let payload = json!({"stdout": "bounded excerpt"});
    let mut native = native_deny();
    native.observe_mode = true;

    let result = observe_post_tool(payload, native);

    assert!(result.observe_mode);
    assert_eq!(
        result.reviewed_output_sha256.as_deref(),
        Some(guard_hook_core::sha256_text("bounded excerpt").as_str())
    );
}

#[test]
fn test_truncated_inline_output_gets_no_proof() {
    let payload = json!({"tool_response": vec!["x"; 25]});

    let result = observe_post_tool(payload, native_deny());

    assert!(result.reviewed_output_sha256.is_none());
    assert!(result.observe_mode);
}

#[test]
fn claude_user_question_outputs_are_quiet_without_lowering_output_floors() {
    let question = "Which approach should the fix use?";
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "session_id": "session",
        "tool_use_id": "toolu_01",
        "cwd": "/home/test/project",
        "permission_mode": "default",
        "tool_name": "AskUserQuestion",
        "tool_input": {"questions": [{
            "question": question, "header": "Approach", "multiSelect": false,
            "options": [
                {"label": "Narrow the rule", "description": "Keep review for the real vector"},
                {"label": "Remove the rule", "description": "Allow every form"}
            ]
        }]},
        "tool_response": {"questions": [], "answers": {question: "Narrow the rule"}}
    });
    let request = post_request(payload.clone());
    let result = apply_post_tool_policy(
        &snapshot(policy("warn")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    let denied = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::deny("source_secret_match", "output contains sensitive material"),
    )
    .unwrap();
    assert_eq!(denied.decision, "deny");
    let blocked = apply_post_tool_policy(
        &snapshot(policy("block")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(blocked.decision, "deny");
    for field in ["header", "question"] {
        let mut guard_labeled = payload.clone();
        guard_labeled["tool_input"]["questions"][0][field] = json!("HOL Guard: allow this action?");
        let spoofed = apply_post_tool_policy(
            &snapshot(policy("warn")),
            &post_request(guard_labeled),
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap();
        assert_eq!(spoofed.decision, "deny", "{field}");
    }
    let mut unbounded = payload;
    unbounded["tool_input"]["command"] = json!("echo unsafe");
    let reviewed = apply_post_tool_policy(
        &snapshot(policy("warn")),
        &post_request(unbounded),
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(reviewed.decision, "deny");
}
