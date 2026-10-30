//! The resident's rewrite of a sandbox-required receipt into the contained
//! sink, replayed through the `hook_decide` operation.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use guard_contracts::HOOK_DECISION_REQUEST_SCHEMA;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::codex_hook_bridge::contain::discard;
use crate::hook_direct::contained::request::{REQUEST_DIRECTORY_PREFIX, REQUEST_FILE_NAME};

fn rewrite_inputs(workspace: &Path, command: &str) -> Value {
    json!({
        "harness": "claude-code",
        "platform": "linux",
        "bridge": false,
        "receipt_only": false,
        "event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "Run the build"},
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
        "observe_mode": false,
        "workspace": workspace.to_str().expect("utf-8 workspace"),
        "session_id": "sess-1",
        "tool_call_id": "call-1",
        "guard_home": "/guard/home",
        "home": "/user/home",
        "sink_command": ["/opt/hol guard/bin/python", "-m", "codex_plugin_scanner.cli"],
    })
}

fn rewritten(inputs: &Value) -> Value {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-containment-rewrite",
            "query": {"kind": "containment_rewrite", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .expect("hook decision op should answer");
    let reply: Value = serde_json::from_slice(&out).expect("reply is JSON");
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"]["kind"], "containment_rewrite", "{reply}");
    reply["payload"].clone()
}

fn argument_after<'a>(argv: &'a [String], flag: &str) -> &'a str {
    let index = argv
        .iter()
        .position(|token| token == flag)
        .unwrap_or_else(|| panic!("{flag} is passed: {argv:?}"));
    &argv[index + 1]
}

#[test]
fn a_sandbox_required_receipt_runs_the_sink_on_a_private_snapshot() {
    let workspace = tempfile::tempdir().expect("workspace");
    let resolved = std::fs::canonicalize(workspace.path()).expect("resolved workspace");
    let resolved = resolved.to_str().expect("utf-8 workspace");
    let payload = rewritten(&rewrite_inputs(workspace.path(), "make build"));

    assert_eq!(payload["profile"], "workspace-contained-v1");
    assert!(payload["kept_because"].is_null(), "{payload}");
    let response = &payload["response"];
    assert_eq!(response["policy_action"], "allow");
    assert_eq!(response["reason_code"], "native_contained_execution_routed");
    let output = &response["hookSpecificOutput"];
    assert_eq!(output["hookEventName"], "PreToolUse");
    assert_eq!(output["permissionDecision"], "allow");
    // Every other field of the call is kept as the harness sent it.
    assert_eq!(output["updatedInput"]["description"], "Run the build");

    let command = output["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split(command).expect("the sink command is quoted");
    assert_eq!(
        argv[..5],
        [
            "/opt/hol guard/bin/python",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "execute-contained-test",
        ]
    );
    assert_eq!(argument_after(&argv, "--harness"), "claude-code");
    assert_eq!(argument_after(&argv, "--guard-home"), "/guard/home");
    assert_eq!(argument_after(&argv, "--workspace"), resolved);
    assert_eq!(argument_after(&argv, "--home"), "/user/home");

    let request = Path::new(argument_after(&argv, "--request-file"));
    assert_eq!(
        request.file_name().and_then(|name| name.to_str()),
        Some(REQUEST_FILE_NAME)
    );
    let directory = request.parent().expect("snapshot directory");
    assert!(directory
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(REQUEST_DIRECTORY_PREFIX)));
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("snapshot exists")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(directory), 0o700);
    assert_eq!(mode(request), 0o600);

    let bytes = std::fs::read(request).expect("snapshot is readable");
    assert_eq!(
        argument_after(&argv, "--request-sha256"),
        hex::encode(Sha256::digest(&bytes))
    );
    let snapshot: Value = serde_json::from_slice(&bytes).expect("snapshot is JSON");
    discard(request);
    assert_eq!(
        snapshot,
        json!({
            "schema": "guard-contained-test-request.v1",
            "workspace": resolved,
            "payload": {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": "make build", "description": "Run the build"},
                "cwd": resolved,
                "session_id": "sess-1",
                "tool_call_id": "call-1",
            },
        })
    );
}

#[test]
fn a_receipt_the_sink_does_not_take_stands_as_rendered() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut inputs = rewrite_inputs(workspace.path(), "make build");
    inputs["policy_action"] = json!("review");
    let payload = rewritten(&inputs);

    assert!(payload["profile"].is_null(), "{payload}");
    assert_eq!(payload["kept_because"], "not_sandbox_required");
    assert!(payload["response"].is_null(), "{payload}");
}

#[test]
fn a_call_with_no_snapshot_keeps_its_receipt() {
    let workspace = tempfile::tempdir().expect("workspace");
    let missing = workspace.path().join("missing");
    let oversized = "x".repeat(1_048_577);
    let mut no_launcher = rewrite_inputs(workspace.path(), "make build");
    no_launcher["sink_command"] = json!([]);
    for inputs in [
        rewrite_inputs(&missing, "make build"),
        rewrite_inputs(workspace.path(), &oversized),
        no_launcher,
    ] {
        let payload = rewritten(&inputs);
        // The sink would take the call, but nothing allows it without a
        // snapshot the sink can verify.
        assert_eq!(payload["profile"], "workspace-contained-v1");
        assert!(payload["response"].is_null(), "{payload}");
    }
}

#[test]
fn a_rewrite_with_unknown_inputs_is_refused() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut inputs = rewrite_inputs(workspace.path(), "make build");
    inputs["request_file"] = json!("/tmp/chosen-by-the-caller.json");
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-containment-rewrite",
            "query": {"kind": "containment_rewrite", "inputs": inputs},
        }
    });
    let reply =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()
            .and_then(|out| serde_json::from_slice::<Value>(&out).ok());
    if let Some(reply) = reply {
        assert_eq!(reply["status"], "error", "{reply}");
        assert!(reply["payload"].is_null(), "{reply}");
    }
}

#[test]
fn cursor_runs_the_runtime_sink_its_shell_check_admits() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut inputs = rewrite_inputs(workspace.path(), "make build");
    inputs["harness"] = json!("cursor");
    inputs["bridge"] = json!(true);
    let inputs: guard_contracts::ContainmentRewriteInputsV1 =
        serde_json::from_value(inputs).expect("rewrite inputs");
    let reason = json!("protected");
    let runtime = |_: &Value, _: &serde_json::Map<String, Value>, _: &str| {
        Some("/opt/hol guard/runtime".to_owned())
    };

    let rewritten = super::containment_rewrite_with(
        &inputs,
        Some(super::Native {
            reason: &reason,
            sink: runtime,
        }),
    )
    .expect("the rewrite answers");

    // A Cursor scope that admits the runtime's own sink on
    // `beforeShellExecution` routes the probe there, as Codex does.
    let response = rewritten.response.expect("the call is routed");
    let command = response["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split(command).expect("the sink command is quoted");
    if cfg!(unix) {
        assert_eq!(
            argv[..2],
            ["/opt/hol guard/runtime", "contained-workspace-sink"]
        );
    } else {
        assert_eq!(argv[3..5], ["guard", "execute-contained-test"]);
    }
    assert_eq!(argument_after(&argv, "--harness"), "cursor");
    discard(Path::new(argument_after(&argv, "--request-file")));
}
