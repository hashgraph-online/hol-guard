//! Cursor's route probe and the contained sink it rewrites a call into.

use super::{
    admit_sink, daemon_answer, probe_answer, route, unreviewed_probe, CursorDefer, Route, Scope,
};
use crate::codex_hook_bridge::contain::discard;
use crate::hook_direct::HookDirectDefer;
use serde_json::{json, Map, Value};
use std::path::Path;

const HOME: &str = "/home/guard";
const GUARD_HOME: &str = "/home/guard/.hol-guard";

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn scope(workspace: &str) -> Scope {
    let sink = ["/opt/hol guard/bin/python".to_owned(), "-I".to_owned()];
    Scope::new(workspace, HOME, GUARD_HOME, Some(&sink)).unwrap()
}

fn probe(command: &str, cwd: &str) -> Map<String, Value> {
    object(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": { "command": command, "cwd": cwd },
        "cwd": cwd,
        "session_id": "sess-1",
        "tool_use_id": "call-1",
        "cursor_route_probe": true,
    }))
}

fn sink_call(command: &str) -> Map<String, Value> {
    object(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": { "command": command },
        "cursor_source_hook_event": "beforeShellExecution",
    }))
}

/// A workspace build the edge sends to the workspace sandbox.
fn sandboxed_edge(containment_route: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-hook-edge-result.v2",
        "harness": "cursor",
        "event_name": "PreToolUse",
        "containment_route": containment_route,
        "harness_response": {},
        "result": {
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
        },
    }))
    .unwrap()
}

fn workspace() -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let resolved = std::fs::canonicalize(directory.path())
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    (directory, resolved)
}

fn routed_command(answer: &Value) -> &str {
    answer["harness_response"]["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap_or_else(|| panic!("the probe routes the call: {answer}"))
}

fn request_file(command: &str) -> String {
    let argv = crate::mcp_proxy_shlex::split_with(command, "", "").unwrap();
    let index = argv
        .iter()
        .position(|token| token == "--request-file")
        .unwrap();
    argv[index + 1].clone()
}

#[test]
fn only_a_named_probe_and_a_before_shell_sink_take_the_cursor_route() {
    let sink = "python -I guard execute-contained-test --harness cursor";
    let unnamed = object(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": { "command": "ls" },
    }));
    let elsewhere = object(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": { "command": sink },
        "cursor_source_hook_event": "beforeMCPExecution",
    }));
    let mut receipt_only = probe("make build", "/repo");
    receipt_only.insert("guard_containment_receipt_only".to_owned(), json!(false));
    let mut receipt_unset = probe("make build", "/repo");
    receipt_unset.insert("guard_containment_receipt_only".to_owned(), Value::Null);
    let write = object(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": "/repo/a", "content": "x" },
    }));

    assert_eq!(route(&write).unwrap(), Route::Review);
    assert_eq!(route(&probe("make build", "/repo")).unwrap(), Route::Probe);
    assert_eq!(route(&receipt_unset).unwrap(), Route::Probe);
    assert_eq!(route(&sink_call(sink)).unwrap(), Route::Sink);
    // The daemon reviews every other call naming the probe or the sink, and
    // each one counts under the reason it was handed over.
    for (payload, reason) in [
        (unnamed, CursorDefer::ProbeUnnamed),
        (elsewhere, CursorDefer::SinkSource),
        (receipt_only, CursorDefer::ReceiptOnly),
    ] {
        assert_eq!(route(&payload), Err(HookDirectDefer::Cursor(reason)));
    }
}

#[test]
fn a_probe_the_sink_cannot_take_is_a_plain_allow_before_any_review() {
    let (_directory, workspace) = workspace();
    let scope = scope(&workspace);
    let allow = json!({ "harness_response": { "policy_action": "allow" } });
    assert_eq!(
        unreviewed_probe(&probe("make build", &workspace), &scope, false),
        None
    );
    // `~` names the hook's home, never the workspace here.
    for payload in [
        probe("make build", "/"),
        probe("make build", "~"),
        probe("make build", "repo"),
        object(json!({ "tool_name": "Shell", "tool_input": { "command": 1 } })),
    ] {
        assert_eq!(
            unreviewed_probe(&payload, &scope, false),
            Some(allow.clone()),
            "{payload:?}"
        );
    }
    // Watch never routes.
    assert_eq!(
        unreviewed_probe(&probe("make build", &workspace), &scope, true),
        Some(allow)
    );
}

#[test]
fn a_sandboxed_probe_runs_in_the_sink_and_the_sink_is_admitted_as_written() {
    let (_directory, workspace) = workspace();
    let scope = scope(&workspace);
    let answer = probe_answer(
        &sandboxed_edge("sink"),
        &probe("make build", &workspace),
        &scope,
    );
    let response = &answer["harness_response"];
    assert_eq!(response["policy_action"], "allow", "{answer}");
    assert_eq!(response["reason_code"], "native_contained_execution_routed");
    let command = routed_command(&answer).to_owned();
    let request = request_file(&command);
    assert!(Path::new(&request).is_file(), "{request}");

    let admitted = admit_sink(&sink_call(&command), &scope).unwrap();
    assert_eq!(
        admitted,
        json!({ "harness_response": {
            "policy_action": "allow",
            "reason_code": "native_contained_execution_routed",
        } })
    );
    // Any other argv takes the daemon's review.
    let other_home = scope_with_guard_home(&workspace, "/elsewhere/.hol-guard");
    let digest_start = command.find("--request-sha256").unwrap() + "--request-sha256 ".len();
    let mut tampered = command.clone();
    tampered.replace_range(digest_start..digest_start + 1, "Z");
    let elsewhere = tempfile::tempdir().unwrap();
    let other_workspace = elsewhere.path().to_str().unwrap();
    // A request outside the temporary directory is no snapshot the rewrite
    // writes.
    let other_request = "/opt/guard-elsewhere/request/request.json";
    for (call, scope, reason) in [
        (sink_call(&command), &other_home, CursorDefer::SinkArgv),
        (sink_call(&tampered), &scope, CursorDefer::SinkArgv),
        (
            sink_call(&format!("{command} --extra")),
            &scope,
            CursorDefer::SinkArgv,
        ),
        (
            sink_call(&command.replace(HOME, "/home/other")),
            &scope,
            CursorDefer::SinkArgv,
        ),
        (
            sink_call(&command.replace(&format!("--home {HOME}"), "--home /home/other")),
            &scope,
            CursorDefer::SinkHome,
        ),
        (
            sink_call(&command.replace(&workspace, other_workspace)),
            &scope,
            CursorDefer::SinkWorkspace,
        ),
        (
            sink_call(&command.replace(&request, other_request)),
            &scope,
            CursorDefer::SinkSnapshot,
        ),
    ] {
        assert_eq!(
            admit_sink(&call, scope),
            Err(HookDirectDefer::Cursor(reason)),
            "{call:?}"
        );
    }
    discard(Path::new(&request));
}

fn scope_with_guard_home(workspace: &str, guard_home: &str) -> Scope {
    let sink = ["/opt/hol guard/bin/python".to_owned(), "-I".to_owned()];
    Scope::new(workspace, HOME, guard_home, Some(&sink)).unwrap()
}

#[test]
fn a_probe_the_edge_keeps_out_of_the_sink_is_a_plain_allow() {
    let (_directory, workspace) = workspace();
    let scope = scope(&workspace);
    let allow = json!({ "harness_response": { "policy_action": "allow" } });
    let payload = probe("make build", &workspace);
    assert_eq!(
        probe_answer(&sandboxed_edge("none"), &payload, &scope),
        allow
    );
    assert_eq!(probe_answer(b"not json", &payload, &scope), allow);
    // A receipt-only probe keeps its receipt, so it is never routed.
    let mut receipt_only = payload.clone();
    receipt_only.insert("guard_containment_receipt_only".to_owned(), json!(true));
    assert_eq!(
        probe_answer(&sandboxed_edge("sink"), &receipt_only, &scope),
        allow
    );
}

#[test]
fn a_cursor_route_needs_the_bound_sink_command() {
    assert!(matches!(
        Scope::new("/repo", HOME, GUARD_HOME, None),
        Err(HookDirectDefer::BindingIncomplete)
    ));
}

fn daemon_params(
    workspace: &str,
    payload: Map<String, Value>,
    edge: Option<Value>,
) -> Map<String, Value> {
    let mut params = object(json!({
        "payload": payload,
        "workspace": workspace,
        "home_dir": HOME,
        "guard_home": GUARD_HOME,
        "sink_command": ["/opt/hol guard/bin/python", "-I"],
    }));
    if let Some(edge) = edge {
        params.insert("edge".to_owned(), edge);
    }
    params
}

#[test]
fn the_daemon_path_routes_a_probe_and_admits_the_sink_it_wrote() {
    let (_directory, workspace) = workspace();
    let edge: Value = serde_json::from_slice(&sandboxed_edge("sink")).unwrap();
    let probe_params = daemon_params(
        &workspace,
        probe("make build", &workspace),
        Some(edge.clone()),
    );
    let response = daemon_answer(&probe_params).unwrap().unwrap();
    let answer = json!({ "harness_response": response });
    let command = routed_command(&answer).to_owned();
    let request = request_file(&command);

    assert_eq!(
        daemon_answer(&daemon_params(&workspace, sink_call(&command), None)).unwrap(),
        Some(json!({
            "policy_action": "allow",
            "reason_code": "native_contained_execution_routed",
        }))
    );
    // A tampered sink call or an ordinary call takes the daemon's review.
    for payload in [
        sink_call(&format!("{command} --extra")),
        object(
            json!({ "hook_event_name": "PreToolUse", "tool_name": "Shell",
                       "tool_input": { "command": "make build" } }),
        ),
    ] {
        assert_eq!(
            daemon_answer(&daemon_params(&workspace, payload.clone(), None)).unwrap(),
            None,
            "{payload:?}"
        );
    }
    // A probe outside the workspace never moves into the sandbox.
    assert_eq!(
        daemon_answer(&daemon_params(
            &workspace,
            probe("make build", "/"),
            Some(edge)
        ))
        .unwrap(),
        Some(json!({ "policy_action": "allow" }))
    );
    discard(Path::new(&request));
}

#[test]
fn the_daemon_path_refuses_a_request_missing_its_binding() {
    let (_directory, workspace) = workspace();
    let mut no_sink = daemon_params(&workspace, probe("make build", &workspace), Some(json!({})));
    no_sink.remove("sink_command");
    let no_edge = daemon_params(&workspace, probe("make build", &workspace), None);
    let mut bad_sink = no_edge.clone();
    bad_sink.insert("sink_command".to_owned(), json!([1]));
    for params in [no_sink, no_edge, bad_sink] {
        assert_eq!(
            daemon_answer(&params),
            Err("native_hook_render_invalid"),
            "{params:?}"
        );
    }
}

#[test]
fn a_native_scope_runs_the_runtime_sink_and_admits_only_this_runtime() {
    let (_directory, workspace) = workspace();
    let scope = scope(&workspace).with_native_sink();
    let answer = probe_answer(
        &sandboxed_edge("sink"),
        &probe("make build", &workspace),
        &scope,
    );
    let command = routed_command(&answer).to_owned();
    let request = request_file(&command);
    let argv = crate::mcp_proxy_shlex::split_with(&command, "", "").unwrap();
    let runtime = std::env::current_exe().unwrap();
    assert_eq!(
        argv[..2],
        [runtime.to_str().unwrap(), "contained-workspace-sink"]
    );
    assert_eq!(route(&sink_call(&command)).unwrap(), Route::Sink);
    assert!(admit_sink(&sink_call(&command), &scope).is_ok());
    // The same argv naming any other executable takes the daemon's review.
    let mut other = argv.clone();
    other[0] = "/opt/elsewhere/hol-guard".to_owned();
    assert_eq!(
        admit_sink(&sink_call(&crate::mcp_proxy_shlex::join(&other)), &scope),
        Err(HookDirectDefer::Cursor(CursorDefer::SinkArgv))
    );
    discard(Path::new(&request));

    // A call that leaves the directory to the top level runs there too.
    let mut plain = probe("make build", &workspace);
    plain.insert("tool_input".to_owned(), json!({ "command": "make build" }));
    let answer = probe_answer(&sandboxed_edge("sink"), &plain, &scope);
    let command = routed_command(&answer).to_owned();
    let argv = crate::mcp_proxy_shlex::split_with(&command, "", "").unwrap();
    assert_eq!(argv[1], "contained-workspace-sink");
    discard(Path::new(&request_file(&command)));
}

#[test]
fn the_daemon_path_runs_the_runtime_sink_only_when_the_daemon_admits_it() {
    let (_directory, workspace) = workspace();
    let edge: Value = serde_json::from_slice(&sandboxed_edge("sink")).unwrap();
    let mut params = daemon_params(&workspace, probe("make build", &workspace), Some(edge));
    let head = |params: &Map<String, Value>| {
        let response = daemon_answer(params).unwrap().unwrap();
        let command = routed_command(&json!({ "harness_response": response })).to_owned();
        discard(Path::new(&request_file(&command)));
        crate::mcp_proxy_shlex::split_with(&command, "", "").unwrap()[1].clone()
    };
    // An older daemon reviews the runtime's sink command, so it gets Guard's.
    assert_eq!(head(&params), "-I");
    params.insert("native_sink".to_owned(), json!(true));
    assert_eq!(head(&params), "contained-workspace-sink");
}
