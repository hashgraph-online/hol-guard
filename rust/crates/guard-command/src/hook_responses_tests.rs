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
        "review"
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

#[test]
fn post_tool_policy_floor_warning_on_a_proven_allow_renders_no_text() {
    let response = obj(&json!({
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "warn",
        "reason_code": "native_policy_warning",
        "notice": "none",
    }));
    for harness in [
        "claude-code",
        "codex",
        "zcode",
        "omp",
        "pi",
        "grok",
        "cursor",
    ] {
        let rendered = Value::Object(post_tool(harness, &response));
        assert_eq!(rendered["policy_action"], "warn", "{harness}");
        let text = rendered.to_string();
        assert!(
            !text.contains("permissionDecisionReason"),
            "{harness}: {text}"
        );
        assert!(
            !text.contains("\"notice\":\"warning\""),
            "{harness}: {text}"
        );
    }
}

#[test]
fn every_watched_ecosystems_package_permission_keeps_the_containment_receipt() {
    let response = |extension: &str| {
        obj(&json!({
            "schema": "guard-pre-tool-result.v1",
            "authority": "rust",
            "decision": "deny",
            "minimum_action": "sandbox-required",
            "policy_action": "sandbox-required",
            "reason_code": "native_workspace_containment_required",
            "reason": "protected",
            "command_extensions": {
                "binding": {"uncertainty_count": 0, "observations_digest": "sha256:fixture"},
                "evaluation_error": null,
                "observations": [],
                "permission_observations": [{
                    "extension_id": extension,
                    "permission_id": format!("{extension}.permission.package-protection"),
                    "uncertainty_reasons": [],
                }],
            },
        }))
    };
    // The firewall marks which ecosystem's manager ran, not a risk the run
    // carries, so a local verb below any of them reaches the sandbox.
    for extension in ["command.package.node", "command.package.python"] {
        for harness in ["zcode", "omp", "codex"] {
            let rendered = pre_tool(harness, &response(extension));
            assert_eq!(
                rendered.get("required_execution_profile"),
                Some(&json!("workspace-contained-v1")),
                "{harness}: {extension}"
            );
            assert_eq!(
                rendered.get("command_binding_digest"),
                Some(&json!("sha256:fixture")),
                "{harness}: {extension}"
            );
        }
    }
    // An extension the firewall does not own says nothing about the verb, so
    // the verdict stays an ordinary block.
    let rendered = pre_tool("zcode", &response("command.network.egress"));
    assert_eq!(rendered.get("required_execution_profile"), None);
    assert_eq!(rendered.get("policy_action"), Some(&json!("block")));
}

#[test]
fn bun_eval_package_permission_keeps_the_node_eval_receipt() {
    let response = |reason_code: &str| {
        obj(&json!({
            "schema": "guard-pre-tool-result.v1",
            "authority": "rust",
            "decision": "deny",
            "minimum_action": "sandbox-required",
            "policy_action": "sandbox-required",
            "reason_code": reason_code,
            "reason": "protected",
            "command_extensions": {
                "binding": {"uncertainty_count": 0},
                "evaluation_error": null,
                "observations": [],
                "permission_observations": [{
                    "extension_id": "command.package.node",
                    "permission_id": "command.package.node.permission.package-protection",
                    "uncertainty_reasons": [],
                }],
            },
        }))
    };
    let rendered = pre_tool(
        "zcode",
        &response("native_bun_eval_readonly_containment_required"),
    );
    assert_eq!(
        rendered.get("required_execution_profile"),
        Some(&json!("node-eval-readonly-v1"))
    );
    assert_eq!(
        rendered.get("reason_code"),
        Some(&json!("native_bun_eval_readonly_containment_required"))
    );
    // `node -e` and Python evaluation never run a package-manager image, so
    // the permission keeps them blocked.
    for (harness, reason) in [
        ("zcode", "native_node_eval_readonly_containment_required"),
        ("omp", "native_node_eval_readonly_containment_required"),
        ("zcode", "native_python_eval_readonly_containment_required"),
    ] {
        let rendered = pre_tool(harness, &response(reason));
        assert_eq!(rendered.get("required_execution_profile"), None, "{reason}");
        assert_eq!(
            rendered.get("policy_action"),
            Some(&json!("block")),
            "{reason}"
        );
    }
}
