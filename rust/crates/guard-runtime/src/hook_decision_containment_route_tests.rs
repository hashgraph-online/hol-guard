//! Containment routing, replayed through the resident `hook_decide` operation.
//!
//! Every host is answered from the request's `platform`, so these run on all
//! three CI hosts, Windows included.

use guard_contracts::HOOK_DECISION_REQUEST_SCHEMA;
use serde_json::{json, Value};

const OUTSIDE_ROOTS: &str = "native_workspace_containment_executable_outside_roots";

fn reply(kind: &str, inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-containment-route",
            "query": {"kind": kind, "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn answered(kind: &str, inputs: &Value) -> Value {
    let reply = reply(kind, inputs).expect("hook decision op should answer");
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"]["kind"], kind, "{reply}");
    reply["payload"].clone()
}

fn rejected(kind: &str, inputs: &Value) -> bool {
    match reply(kind, inputs) {
        None => true,
        Some(reply) => reply["status"] == "error" && reply["payload"].is_null(),
    }
}

fn route_inputs(minimum: &str, policy: &str, reason: &str) -> Value {
    json!({
        "event_name": "PreToolUse",
        "recording_only": false,
        "minimum_action": minimum,
        "policy_action": policy,
        "reason_code": reason,
        "action_type": "shell",
    })
}

fn route(inputs: &Value) -> String {
    answered("containment_route", inputs)["route"]
        .as_str()
        .expect("route is text")
        .to_owned()
}

fn sink_inputs(platform: &str, harness: &str, reason: &str, profile: &str) -> Value {
    json!({
        "harness": harness,
        "platform": platform,
        "bridge": false,
        "receipt_only": false,
        "event_name": "PreToolUse",
        "tool_name": "Bash",
        "command_is_text": true,
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": reason,
        "required_execution_profile": profile,
        "observe_mode": false,
    })
}

fn pytest_inputs(platform: &str, harness: &str) -> Value {
    sink_inputs(
        platform,
        harness,
        "native_pytest_readonly_containment_required",
        "pytest-readonly-v2",
    )
}

fn workspace_inputs(platform: &str, harness: &str) -> Value {
    sink_inputs(
        platform,
        harness,
        "native_workspace_containment_required",
        "workspace-contained-v1",
    )
}

/// `(profile, kept_because)`.
fn sink(inputs: &Value) -> (Option<String>, Option<String>) {
    let payload = answered("containment_sink", inputs);
    let text = |name: &str| payload[name].as_str().map(str::to_owned);
    (text("profile"), text("kept_because"))
}

fn kept(inputs: &Value) -> String {
    let (profile, kept_because) = sink(inputs);
    assert_eq!(profile, None, "{inputs}");
    kept_because.expect("a kept receipt says why")
}

fn with(mut inputs: Value, field: &str, value: Value) -> Value {
    inputs[field] = value;
    inputs
}

#[test]
fn a_review_keeps_allow_once_and_always_allow() {
    // An ordinary review is not routed: it keeps its card with Allow once and
    // Always allow. Only an outside-roots review a grant may lift asks the
    // grant, and the sink never takes a review receipt itself.
    assert_eq!(
        route(&route_inputs(
            "review",
            "review",
            "native_unrecognized_command"
        )),
        "none"
    );
    assert_eq!(
        route(&route_inputs(
            "require-reapproval",
            "require-reapproval",
            OUTSIDE_ROOTS
        )),
        "none"
    );
    assert_eq!(
        route(&route_inputs("review", "review", OUTSIDE_ROOTS)),
        "grant"
    );
    let review = with(
        pytest_inputs("macos", "claude-code"),
        "policy_action",
        json!("review"),
    );
    assert_eq!(kept(&review), "not_sandbox_required");
}

#[test]
fn a_sandbox_requirement_goes_to_the_sink() {
    assert_eq!(
        route(&route_inputs(
            "sandbox-required",
            "sandbox-required",
            "native_pytest_readonly_containment_required"
        )),
        "sink"
    );
    // Either field names the tier: the sink reads the rendered receipt.
    assert_eq!(
        route(&route_inputs("block", "sandbox-required", "x")),
        "sink"
    );
}

#[test]
fn watch_and_other_events_are_never_routed() {
    let watched = with(
        route_inputs("sandbox-required", "sandbox-required", "x"),
        "recording_only",
        json!(true),
    );
    assert_eq!(route(&watched), "none");
    let post = with(
        route_inputs("sandbox-required", "sandbox-required", "x"),
        "event_name",
        json!("PostToolUse"),
    );
    assert_eq!(route(&post), "none");
    let unnamed = with(
        route_inputs("sandbox-required", "sandbox-required", "x"),
        "event_name",
        Value::Null,
    );
    assert_eq!(route(&unnamed), "none");
    let watched_review = with(
        route_inputs("review", "review", OUTSIDE_ROOTS),
        "recording_only",
        json!(true),
    );
    assert_eq!(route(&watched_review), "none");
}

#[test]
fn guard_control_and_package_reviews_never_reach_the_grant() {
    for action_type in [
        json!("guard_control"),
        json!("guard-control"),
        json!("guard_control_operation"),
        json!("guard-control-operation"),
        json!("package"),
        json!(["shell"]),
        json!({"kind": "shell"}),
    ] {
        let inputs = with(
            route_inputs("review", "review", OUTSIDE_ROOTS),
            "action_type",
            action_type,
        );
        assert_eq!(route(&inputs), "none", "{inputs}");
    }
    for action_type in [Value::Null, json!(7), json!("shell")] {
        let inputs = with(
            route_inputs("review", "review", OUTSIDE_ROOTS),
            "action_type",
            action_type,
        );
        assert_eq!(route(&inputs), "grant", "{inputs}");
    }
    let partial = route_inputs("review", "block", OUTSIDE_ROOTS);
    assert_eq!(route(&partial), "none");
}

#[test]
fn macos_runs_every_profile() {
    assert_eq!(
        sink(&pytest_inputs("macos", "claude-code")).0.as_deref(),
        Some("pytest-readonly-v2")
    );
    assert_eq!(
        sink(&workspace_inputs("macos", "zcode")).0.as_deref(),
        Some("workspace-contained-v1")
    );
    let git = sink_inputs(
        "macos",
        "zcode",
        "native_git_readonly_containment_required",
        "git-readonly-v1",
    );
    assert_eq!(sink(&git).0.as_deref(), Some("git-readonly-v1"));
}

#[test]
fn linux_runs_only_the_workspace_sandbox() {
    assert_eq!(
        sink(&workspace_inputs("linux", "claude-code")).0.as_deref(),
        Some("workspace-contained-v1")
    );
    assert_eq!(
        kept(&pytest_inputs("linux", "claude-code")),
        "platform_has_no_sink"
    );
}

#[test]
fn windows_names_the_profiles_its_sink_runs() {
    for (reason, profile) in [
        (
            "native_python_eval_readonly_containment_required",
            "python-eval-readonly-v1",
        ),
        (
            "native_node_eval_readonly_containment_required",
            "node-eval-readonly-v1",
        ),
        (
            "native_bun_eval_readonly_containment_required",
            "node-eval-readonly-v1",
        ),
        (
            "native_node_build_output_containment_required",
            "node-build-output-v1",
        ),
        (
            "native_node_tool_readonly_containment_required",
            "node-tool-readonly-v1",
        ),
        (
            "native_pytest_readonly_containment_required",
            "pytest-readonly-v2",
        ),
    ] {
        let inputs = sink_inputs("windows", "claude-code", reason, profile);
        assert_eq!(sink(&inputs).0.as_deref(), Some(profile), "{inputs}");
    }
    // A profile with no Windows sink is kept, and says why: never allowed.
    assert_eq!(
        kept(&workspace_inputs("windows", "claude-code")),
        "platform_has_no_sink"
    );
    let package = sink_inputs(
        "windows",
        "claude-code",
        "native_package_test_readonly_containment_required",
        "package-test-readonly-v1",
    );
    assert_eq!(kept(&package), "platform_has_no_sink");
}

#[test]
fn windows_routes_only_claude_code_and_the_codex_bridge() {
    assert_eq!(
        kept(&pytest_inputs("windows", "zcode")),
        "platform_has_no_sink"
    );
    let bridged = with(pytest_inputs("windows", "codex"), "bridge", json!(true));
    assert_eq!(sink(&bridged).0.as_deref(), Some("pytest-readonly-v2"));
}

#[test]
fn a_host_with_no_sink_says_so() {
    assert_eq!(
        kept(&pytest_inputs("other", "claude-code")),
        "platform_has_no_sink"
    );
    assert_eq!(
        kept(&workspace_inputs("other", "zcode")),
        "platform_has_no_sink"
    );
}

#[test]
fn codex_is_routed_only_by_its_bridge() {
    assert_eq!(kept(&pytest_inputs("macos", "codex")), "harness_not_routed");
    let bridged = with(pytest_inputs("macos", "codex"), "bridge", json!(true));
    assert_eq!(sink(&bridged).0.as_deref(), Some("pytest-readonly-v2"));
    for harness in ["omp", "cursor", "Claude-Code", ""] {
        let inputs = pytest_inputs("macos", harness);
        assert_eq!(kept(&inputs), "harness_not_routed", "{inputs}");
    }
}

#[test]
fn the_receipt_stands_for_every_unroutable_shape() {
    let base = pytest_inputs("macos", "claude-code");
    let cases = [
        ("receipt_only", json!(true), "receipt_only"),
        ("decision", json!("allow"), "not_sandbox_required"),
        ("policy_action", json!("block"), "not_sandbox_required"),
        ("observe_mode", json!(true), "observe_mode"),
        (
            "required_execution_profile",
            json!("workspace-contained-v1"),
            "profile_mismatch",
        ),
        ("reason_code", json!("native_unknown"), "profile_mismatch"),
        ("reason_code", Value::Null, "profile_mismatch"),
        ("event_name", json!("PostToolUse"), "not_shell_call"),
        ("tool_name", json!("Write"), "not_shell_call"),
        ("tool_name", Value::Null, "not_shell_call"),
        ("command_is_text", json!(false), "not_shell_call"),
    ];
    for (field, value, why) in cases {
        let inputs = with(base.clone(), field, value);
        assert_eq!(kept(&inputs), why, "{inputs}");
    }
    let snake = with(base, "event_name", json!("pre_tool_use"));
    assert_eq!(sink(&snake).0.as_deref(), Some("pytest-readonly-v2"));
}

#[test]
fn a_native_bash_owner_is_never_rewritten_into_the_sink() {
    let inputs = sink_inputs(
        "macos",
        "claude-code",
        guard_contracts::NATIVE_BASH_DELIVERY_REASON,
        guard_contracts::NATIVE_BASH_DELIVERY_PROFILE,
    );
    assert_eq!(kept(&inputs), "profile_mismatch");
}

#[test]
fn malformed_queries_are_errors_not_routes() {
    assert!(rejected(
        "containment_sink",
        &with(pytest_inputs("macos", "zcode"), "platform", json!("darwin"))
    ));
    assert!(rejected(
        "containment_sink",
        &with(pytest_inputs("macos", "zcode"), "extra", json!(1))
    ));
    let mut missing = pytest_inputs("macos", "zcode");
    missing.as_object_mut().expect("object").remove("bridge");
    assert!(rejected("containment_sink", &missing));
    assert!(rejected(
        "containment_route",
        &with(
            route_inputs("review", "review", OUTSIDE_ROOTS),
            "extra",
            json!(1)
        )
    ));
    assert!(rejected(
        "containment_route",
        &with(
            route_inputs("review", "review", OUTSIDE_ROOTS),
            "recording_only",
            json!("no")
        )
    ));
}

#[test]
fn the_edge_carries_the_route_the_query_answers() {
    // The edge stamps the route so a hook does not ask for it again; it must
    // be the same answer the query gives for the same result.
    let cases = [
        (
            "sandbox-required",
            "sandbox-required",
            "native_contained_python_eval",
            "shell",
            false,
        ),
        (
            "review",
            "sandbox-required",
            "native_contained_python_eval",
            "shell",
            false,
        ),
        ("review", "review", OUTSIDE_ROOTS, "shell", false),
        ("review", "review", OUTSIDE_ROOTS, "guard_control", false),
        ("review", "review", "ordinary_review", "shell", false),
        ("allow", "allow", "allowed", "shell", false),
        (
            "sandbox-required",
            "sandbox-required",
            "native_contained_python_eval",
            "shell",
            true,
        ),
    ];
    for (minimum, policy, reason, action_type, recording_only) in cases {
        let result = json!({
            "minimum_action": minimum,
            "policy_action": policy,
            "reason_code": reason,
            "action": {"action_type": action_type},
        });
        let mut inputs = route_inputs(minimum, policy, reason);
        inputs["action_type"] = json!(action_type);
        inputs["recording_only"] = json!(recording_only);
        assert_eq!(
            super::edge_route("PreToolUse", &result, recording_only),
            route(&inputs),
            "{result}"
        );
    }
    let bare = json!({"minimum_action": "sandbox-required"});
    assert_eq!(super::edge_route("PreToolUse", &bare, false), "sink");
    assert_eq!(super::edge_route("PostToolUse", &bare, false), "none");
}
