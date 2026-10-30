//! The edge's own containment rewrite of a sink-routed `PreToolUse`.

use std::path::Path;

use guard_contracts::{
    GuardHookContainmentSinkV1, GuardHookEnvelopeV2, GuardHookSourceMetadataV2,
    GUARD_HOOK_ENVELOPE_V2_SCHEMA,
};
use serde_json::{json, Map, Value};

use super::{cursor_probe, rewrite, KEPT, ROUTED};
use crate::codex_hook_bridge::contain::discard;

const SINK_COMMAND: [&str; 3] = [
    "/opt/hol guard/bin/python",
    "-m",
    "codex_plugin_scanner.cli",
];

fn envelope(workspace: &Path, sink: bool) -> GuardHookEnvelopeV2 {
    GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: Some("edge-containment".to_owned()),
        harness: "claude-code".to_owned(),
        event: "PreToolUse".to_owned(),
        raw_payload: json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "make build", "description": "Run the build"},
            "session_id": "sess-1",
            "tool_call_id": "call-1",
        }),
        deadline_budget_ms: Some(100),
        policy_generation: 1,
        policy_snapshot: Value::Null,
        source: GuardHookSourceMetadataV2 {
            cwd: Some(workspace.to_str().expect("utf-8 workspace").to_owned()),
            home_dir: "/user/home".to_owned(),
            guard_home: "/guard/home".to_owned(),
            source_ref_external_allowed: false,
            execution_environment: None,
        },
        recording_only: false,
        local_cli_rules: None,
        observe_local_cli: false,
        record_receipt: false,
        structured_output_config: None,
        containment_sink: sink.then(|| GuardHookContainmentSinkV1 {
            sink_command: SINK_COMMAND.map(str::to_owned).to_vec(),
            native_sink: false,
        }),
    }
}

fn sandbox_required() -> Value {
    json!({
        "decision": "deny",
        "minimum_action": "sandbox-required",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
    })
}

/// The workspace-sandbox receipt the edge renders for Claude Code.
fn receipt() -> Value {
    json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "reason": "protected",
        "required_execution_profile": "workspace-contained-v1",
        "command_binding_digest": "sha256:fixture",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "protected",
        },
    })
}

fn no_native(_: &Value, _: &Map<String, Value>, _: &str) -> Option<String> {
    None
}

/// The runtime's own sink, for any call it is asked about.
fn runtime_sink(_: &Value, _: &Map<String, Value>, _: &str) -> Option<String> {
    Some("/opt/hol guard/runtime".to_owned())
}

fn argument_after<'a>(argv: &'a [String], flag: &str) -> &'a str {
    let index = argv
        .iter()
        .position(|token| token == flag)
        .unwrap_or_else(|| panic!("{flag} is passed: {argv:?}"));
    &argv[index + 1]
}

#[test]
fn a_sink_routed_call_comes_back_as_the_routed_allow() {
    let workspace = tempfile::tempdir().expect("workspace");
    let resolved = std::fs::canonicalize(workspace.path()).expect("resolved workspace");
    let request = envelope(&resolved, true);
    let mut response = Some(receipt());

    let answer = rewrite(
        &request,
        "claude-code",
        "sink",
        &sandbox_required(),
        false,
        &mut response,
        no_native,
    );

    assert_eq!(answer, Some(ROUTED));
    let response = response.expect("a response");
    assert_eq!(response["policy_action"], "allow");
    assert_eq!(response["reason_code"], "native_contained_execution_routed");
    let output = &response["hookSpecificOutput"];
    assert_eq!(output["permissionDecision"], "allow");
    assert_eq!(output["updatedInput"]["description"], "Run the build");
    let command = output["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split(command).expect("the sink command is quoted");
    assert_eq!(argv[..3], SINK_COMMAND);
    assert_eq!(argv[3..5], ["guard", "execute-contained-test"]);
    assert_eq!(argument_after(&argv, "--harness"), "claude-code");
    assert_eq!(argument_after(&argv, "--guard-home"), "/guard/home");
    assert_eq!(
        argument_after(&argv, "--workspace"),
        resolved.to_str().expect("utf-8 workspace")
    );
    assert_eq!(argument_after(&argv, "--home"), "/user/home");
    discard(Path::new(argument_after(&argv, "--request-file")));
}

#[test]
fn a_call_the_runtime_reproduces_runs_its_own_sink() {
    let workspace = tempfile::tempdir().expect("workspace");
    let resolved = std::fs::canonicalize(workspace.path()).expect("resolved workspace");
    let request = envelope(&resolved, true);
    let mut response = Some(receipt());

    let answer = rewrite(
        &request,
        "claude-code",
        "sink",
        &sandbox_required(),
        false,
        &mut response,
        runtime_sink,
    );

    assert_eq!(answer, Some(ROUTED));
    let response = response.expect("a response");
    let command = response["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split(command).expect("the sink command is quoted");
    assert_eq!(
        argv[..2],
        ["/opt/hol guard/runtime", "contained-workspace-sink"]
    );
    assert_eq!(argument_after(&argv, "--harness"), "claude-code");
    assert_eq!(argument_after(&argv, "--guard-home"), "/guard/home");
    assert_eq!(argument_after(&argv, "--home"), "/user/home");
    discard(Path::new(argument_after(&argv, "--request-file")));
}

#[test]
fn a_receipt_without_its_reason_keeps_guards_sink() {
    let workspace = tempfile::tempdir().expect("workspace");
    let resolved = std::fs::canonicalize(workspace.path()).expect("resolved workspace");
    let request = envelope(&resolved, true);
    let mut unexplained = receipt();
    unexplained
        .as_object_mut()
        .expect("receipt is an object")
        .remove("reason");
    let mut response = Some(unexplained);

    let answer = rewrite(
        &request,
        "claude-code",
        "sink",
        &sandbox_required(),
        false,
        &mut response,
        runtime_sink,
    );

    // Without the reason the edge cannot tell a chain whose host step the
    // runtime's sink does not run, so the call keeps the sink that does.
    assert_eq!(answer, Some(ROUTED));
    let response = response.expect("a response");
    let command = response["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split(command).expect("the sink command is quoted");
    assert_eq!(argv[..3], SINK_COMMAND);
    assert_eq!(argv[3..5], ["guard", "execute-contained-test"]);
    discard(Path::new(argument_after(&argv, "--request-file")));
}

#[test]
fn without_the_sink_argv_the_receipt_stands_unanswered() {
    let workspace = tempfile::tempdir().expect("workspace");
    let request = envelope(workspace.path(), false);
    let mut response = Some(receipt());

    let answer = rewrite(
        &request,
        "claude-code",
        "sink",
        &sandbox_required(),
        false,
        &mut response,
        no_native,
    );

    // Not answered, so the daemon asks the resident as before.
    assert_eq!(answer, None);
    assert_eq!(response, Some(receipt()));
}

#[test]
fn a_receipt_the_sink_does_not_take_is_kept() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut request = envelope(workspace.path(), true);
    request.raw_payload["guard_containment_receipt_only"] = json!(true);
    let mut response = Some(receipt());

    let answer = rewrite(
        &request,
        "claude-code",
        "sink",
        &sandbox_required(),
        false,
        &mut response,
        no_native,
    );

    assert_eq!(answer, Some(KEPT));
    assert_eq!(response, Some(receipt()));
}

#[test]
fn only_a_sink_route_the_daemon_would_rewrite_is_answered() {
    let workspace = tempfile::tempdir().expect("workspace");
    let request = envelope(workspace.path(), true);
    let mut watched = envelope(workspace.path(), true);
    watched.recording_only = true;
    let mut review = sandbox_required();
    review["minimum_action"] = json!("review");
    for (request, route, result, custom_block) in [
        (&request, "none", sandbox_required(), false),
        (&request, "grant", sandbox_required(), false),
        (&watched, "sink", sandbox_required(), false),
        (&request, "sink", review, false),
        (&request, "sink", sandbox_required(), true),
    ] {
        let mut response = Some(receipt());
        let answer = rewrite(
            request,
            "claude-code",
            route,
            &result,
            custom_block,
            &mut response,
            no_native,
        );
        assert_eq!(answer, None, "{route}");
        assert_eq!(response, Some(receipt()), "{route}");
    }
}

/// Cursor's route probe for `make build` in `workspace`, as Guard's hook
/// names it.
fn cursor_probe_envelope(workspace: &str, sink: bool) -> GuardHookEnvelopeV2 {
    let mut request = envelope(Path::new(workspace), sink);
    request.harness = "cursor".to_owned();
    request.raw_payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "make build", "cwd": workspace},
        "cwd": workspace,
        "session_id": "sess-1",
        "tool_use_id": "call-1",
        "cursor_route_probe": true,
    });
    request
}

/// The workspace build the edge sends to the workspace sandbox.
fn sandboxed_build() -> Value {
    json!({
        "schema": "guard-pre-tool-result.v1",
        "authority": "rust",
        "decision": "deny",
        "minimum_action": "sandbox-required",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "reason": "protected",
        "command_extensions": {
            "binding": {"uncertainty_count": 0, "observations_digest": "0".repeat(64)},
            "evaluation_error": null,
            "observations": [],
            "permission_observations": [{
                "extension_id": "command.package.node",
                "permission_id": "command.package.node.permission.package-protection",
                "uncertainty_reasons": [],
            }],
        },
    })
}

#[test]
fn a_sink_routed_cursor_probe_comes_back_as_the_sink_command() {
    let directory = tempfile::tempdir().expect("workspace");
    let resolved = std::fs::canonicalize(directory.path()).expect("resolved workspace");
    let workspace = resolved.to_str().expect("utf-8 workspace");
    let request = cursor_probe_envelope(workspace, true);
    let mut response = Some(json!({}));

    let answer = cursor_probe(
        &request,
        "cursor",
        "PreToolUse",
        "sink",
        &sandboxed_build(),
        &mut response,
    );

    assert_eq!(answer, Some(ROUTED));
    let response = response.expect("a response");
    assert_eq!(response["policy_action"], "allow");
    assert_eq!(response["reason_code"], "native_contained_execution_routed");
    let command = response["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split_with(command, "", "").expect("quoted");
    assert_eq!(argv[..3], SINK_COMMAND);
    assert_eq!(argument_after(&argv, "--harness"), "cursor");
    assert_eq!(argument_after(&argv, "--workspace"), workspace);
    discard(Path::new(argument_after(&argv, "--request-file")));

    // A daemon that admits the runtime's own sink gets that sink instead.
    let mut native = cursor_probe_envelope(workspace, true);
    if let Some(sink) = native.containment_sink.as_mut() {
        sink.native_sink = true;
    }
    let mut response = Some(json!({}));
    let answer = cursor_probe(
        &native,
        "cursor",
        "PreToolUse",
        "sink",
        &sandboxed_build(),
        &mut response,
    );
    assert_eq!(answer, Some(ROUTED));
    let response = response.expect("a response");
    let command = response["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split_with(command, "", "").expect("quoted");
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let runtime = std::env::current_exe().expect("runtime");
        assert_eq!(
            argv[..2],
            [
                runtime.to_str().expect("utf-8 runtime"),
                "contained-workspace-sink"
            ]
        );
    } else {
        assert_eq!(argv[..3], SINK_COMMAND);
    }
    discard(Path::new(argument_after(&argv, "--request-file")));
}

#[test]
fn a_cursor_probe_the_sink_cannot_take_is_the_plain_allow() {
    let directory = tempfile::tempdir().expect("workspace");
    let resolved = std::fs::canonicalize(directory.path()).expect("resolved workspace");
    let workspace = resolved.to_str().expect("utf-8 workspace");
    let mut watched = cursor_probe_envelope(workspace, true);
    watched.recording_only = true;
    let mut elsewhere = cursor_probe_envelope(workspace, true);
    elsewhere.raw_payload["cwd"] = json!("/somewhere/else");
    for request in [&watched, &elsewhere] {
        let mut response = Some(json!({}));
        let answer = cursor_probe(
            request,
            "cursor",
            "PreToolUse",
            "sink",
            &sandboxed_build(),
            &mut response,
        );
        assert_eq!(answer, Some(KEPT));
        assert_eq!(response, Some(json!({"policy_action": "allow"})));
    }
}

#[test]
fn only_a_sink_routed_cursor_probe_is_answered_as_one() {
    let directory = tempfile::tempdir().expect("workspace");
    let workspace = directory.path().to_str().expect("utf-8 workspace");
    let probe = cursor_probe_envelope(workspace, true);
    let unbound = cursor_probe_envelope(workspace, false);
    let mut shell = cursor_probe_envelope(workspace, true);
    shell.raw_payload["cursor_source_hook_event"] = json!("beforeShellExecution");
    for (request, harness, route) in [
        (&probe, "cursor", "none"),
        (&probe, "cursor", "grant"),
        (&probe, "claude-code", "sink"),
        (&unbound, "cursor", "sink"),
        (&shell, "cursor", "sink"),
    ] {
        let mut response = Some(json!({}));
        let answer = cursor_probe(
            request,
            harness,
            "PreToolUse",
            route,
            &sandboxed_build(),
            &mut response,
        );
        assert_eq!(answer, None, "{harness} {route}");
        assert_eq!(response, Some(json!({})), "{harness} {route}");
    }
}
