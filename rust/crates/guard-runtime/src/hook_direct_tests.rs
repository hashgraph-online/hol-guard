use super::{
    cursor, direct_event, evaluate, expanduser, normalized_workspace, normpath, post_tool_answer,
    pre_tool_answer, prompt_answer, workspace_candidate, HookDirectDefer, HookDirectRequestV1,
    REPAIRABLE_BLOCK_REASON,
};
use crate::policy_store::policy_store_direct_lane::tests::{
    allowing_fixture, binding, fixture, push, write_current_ack, Fixture,
};
use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use serde_json::{json, Map, Value};
use std::fs;

const HOME: &str = "/home/guard";

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn event_name_follows_the_daemon_rule() {
    assert_eq!(direct_event(&object(json!({}))), Ok(Some("PreToolUse")));
    for name in [
        "PreToolUse",
        " pre_tool_use ",
        "pre-tool-call",
        "beforeShellExecution",
    ] {
        assert_eq!(
            direct_event(&object(json!({ "hook_event_name": name }))),
            Ok(Some("PreToolUse")),
            "{name}"
        );
    }
    for name in ["PostToolUse", "post_tool_call", " afterShellExecution "] {
        assert_eq!(
            direct_event(&object(json!({ "hook_event_name": name }))),
            Ok(Some("PostToolUse")),
            "{name}"
        );
    }
    for name in ["UserPromptSubmit", "prompt", "user-prompt-submitted"] {
        assert_eq!(
            direct_event(&object(json!({ "hook_event_name": name }))),
            Ok(Some("UserPromptSubmit")),
            "{name}"
        );
    }
    assert_eq!(
        direct_event(&object(json!({ "hook_event_name": "PostToolUseFailure" }))),
        Ok(None)
    );
    // A blank or non-string field is skipped; the next named field decides.
    assert_eq!(
        direct_event(&object(
            json!({ "event": "  ", "eventName": 3, "hookName": "Stop" })
        )),
        Ok(None)
    );
    assert_eq!(
        direct_event(&object(json!({ "event": "pretool", "hookName": "Stop" }))),
        Ok(Some("PreToolUse"))
    );
    assert_eq!(
        direct_event(&object(json!({ "event": "prétool" }))),
        Ok(None)
    );
}

#[test]
fn workspace_strings_normalize_like_the_daemon() {
    let normalized = |value: &str| normalized_workspace(Some(value), HOME);
    assert_eq!(
        normalized(" /work/./repo/ "),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/a/../repo"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("~/repo"),
        Ok(Some("/home/guard/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/repo/None"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(
        normalized("/work/repo//None"),
        Ok(Some("/work/repo".to_owned()))
    );
    assert_eq!(normalized("/None"), Ok(Some("/".to_owned())));
    for absent in ["", "  ", "none", "NULL", "None"] {
        assert_eq!(normalized(absent), Ok(None), "{absent:?}");
    }
    assert_eq!(normalized_workspace(None, HOME), Ok(None));
    for invalid in [
        "relative/repo",
        "~other/repo",
        "//work/repo",
        "/work\u{1f}repo",
    ] {
        assert_eq!(
            normalized(invalid),
            Err(HookDirectDefer::WorkspaceInvalid),
            "{invalid:?}"
        );
    }
    assert_eq!(normpath("///work//repo"), Ok("/work/repo".to_owned()));
    assert_eq!(expanduser("~", HOME), Ok(HOME.to_owned()));
}

#[test]
fn workspace_prefers_exec_command_workdir_then_cwd_then_query() {
    let payload = object(json!({
        "tool_name": " Exec_Command ",
        "tool_input": { "workdir": "/work/action" },
        "cwd": "/work/cwd",
    }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/action".to_owned()))
    );
    let payload = object(json!({ "tool_name": "read_file", "cwd": "/work/cwd" }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/cwd".to_owned()))
    );
    let payload = object(json!({ "cwd": "None" }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Ok(Some("/work/query".to_owned()))
    );
    assert_eq!(
        workspace_candidate(&object(json!({})), None, HOME),
        Ok(None)
    );
    // The daemon rejects a present but unusable workdir instead of skipping it.
    for workdir in [json!(null), json!(""), json!("none"), json!(7)] {
        let payload = object(json!({
            "tool_name": "exec_command",
            "tool_input": { "workdir": workdir },
            "cwd": "/work/cwd",
        }));
        assert_eq!(
            workspace_candidate(&payload, None, HOME),
            Err(HookDirectDefer::WorkspaceInvalid)
        );
    }
}

fn edge(decision: &str, minimum_action: &str) -> Vec<u8> {
    pre_edge(json!({ "decision": decision, "minimum_action": minimum_action }))
}

fn pre_edge(result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-hook-edge-result.v2",
        "event_name": "PreToolUse",
        "result": result,
        "harness_response": {},
    }))
    .unwrap()
}

#[test]
fn only_a_verdict_the_daemon_passes_through_is_answered() {
    for (decision, minimum_action) in [
        ("allow", "allow"),
        ("allow", "warn"),
        ("deny", "block"),
        ("deny", "sandbox-required"),
    ] {
        let answered = pre_tool_answer(&edge(decision, minimum_action), false).unwrap();
        assert_eq!(answered["result"]["minimum_action"], minimum_action);
    }
    for (decision, minimum_action) in [
        ("deny", "review"),
        ("deny", "require-reapproval"),
        ("allow", "review"),
        ("allow", "require-reapproval"),
        ("allow", "block"),
        ("deny", "warn"),
        ("deny", "allow"),
    ] {
        assert_eq!(
            pre_tool_answer(&edge(decision, minimum_action), false),
            Err(HookDirectDefer::NotAllow),
            "{decision} {minimum_action}"
        );
    }
    let mut missing_response: Value = serde_json::from_slice(&edge("allow", "allow")).unwrap();
    missing_response
        .as_object_mut()
        .unwrap()
        .remove("harness_response");
    assert_eq!(
        pre_tool_answer(&serde_json::to_vec(&missing_response).unwrap(), false),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        pre_tool_answer(b"not json", false),
        Err(HookDirectDefer::EdgeFailed)
    );
}

#[test]
fn a_block_the_daemon_can_offer_to_repair_defers() {
    // The daemon adds its repair link to this denial.
    let repairable = pre_edge(json!({
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_control_authority_block",
    }));
    assert_eq!(
        pre_tool_answer(&repairable, false),
        Err(HookDirectDefer::NotAllow)
    );
    let other = pre_edge(json!({
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_destructive",
    }));
    assert!(pre_tool_answer(&other, false).is_ok());
}

#[test]
fn a_claude_code_sandbox_requirement_defers_to_contained_execution() {
    // The daemon rewrites this Claude Code denial into a contained run.
    assert_eq!(
        pre_tool_answer(&edge("deny", "sandbox-required"), true),
        Err(HookDirectDefer::NotAllow)
    );
    assert!(pre_tool_answer(&edge("deny", "block"), true).is_ok());
    assert!(pre_tool_answer(&edge("deny", "sandbox-required"), false).is_ok());
}

fn post_edge(result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-hook-edge-result.v2",
        "event_name": "PostToolUse",
        "result": result,
        "harness_response": {},
    }))
    .unwrap()
}

#[test]
fn every_reviewed_post_tool_use_is_answered() {
    let blocked = json!({ "decision": "block", "minimum_action": "block" });
    let answered = post_tool_answer(&post_edge(blocked.clone())).unwrap();
    assert_eq!(answered["result"], blocked);
    assert_eq!(
        post_tool_answer(&post_edge(json!("allow"))),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        post_tool_answer(&edge("allow", "allow")),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        pre_tool_answer(
            &post_edge(json!({ "decision": "allow", "minimum_action": "allow" })),
            false
        ),
        Err(HookDirectDefer::EdgeFailed)
    );
}

struct Lane {
    fixture: Fixture,
    workspace: String,
}

fn lane(label: &str, extra: Value) -> Lane {
    open_lane(label, extra, false)
}

fn allowing_lane(label: &str, extra: Value) -> Lane {
    open_lane(label, extra, true)
}

fn open_lane(label: &str, extra: Value, allow_policy: bool) -> Lane {
    let fixture = if allow_policy {
        allowing_fixture(&format!("hook-direct-{label}"))
    } else {
        fixture(&format!("hook-direct-{label}"))
    };
    let directory = fixture.root.join("repo");
    fs::create_dir_all(&directory).unwrap();
    let workspace = fs::canonicalize(&directory)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut bound = binding(&fixture, &workspace);
    bound["home_dir"] = json!(HOME);
    bound["harness_postures"] = json!({});
    bound["local_cli_block_rules"] = json!(false);
    bound["evidence_drain"] = json!(true);
    for (key, value) in extra.as_object().unwrap() {
        bound[key] = value.clone();
    }
    push(&fixture, Some(bound)).unwrap();
    write_current_ack(&fixture);
    Lane { fixture, workspace }
}

fn run(lane: &Lane, payload: Value) -> Value {
    run_as(lane, "codex", Some(HOME), payload)
}

fn run_as(lane: &Lane, harness: &str, home_dir: Option<&str>, payload: Value) -> Value {
    let request = HookDirectRequestV1 {
        harness: harness.to_owned(),
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        home_dir: home_dir.map(str::to_owned),
        workspace: None,
        deadline_budget_ms: None,
        payload,
    };
    serde_json::from_slice(&evaluate(request, &lane.fixture.store).unwrap()).unwrap()
}

/// A shell command the edge allows outright.
fn allowed_payload(lane: &Lane) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "pwd" },
        "cwd": lane.workspace,
    })
}

fn deferred(result: &Value) -> &str {
    assert_eq!(result["schema"], "guard-hook-direct-result.v1");
    assert_eq!(result["outcome"], "defer", "{result}");
    result["reason"].as_str().unwrap()
}

#[test]
fn request_shapes_the_daemon_must_handle_defer() {
    let lane = lane("shapes", json!({}));
    let mut probe = allowed_payload(&lane);
    probe["guard_transition_probe"] = json!({});
    assert_eq!(deferred(&run(&lane, probe)), "direct_hook_transition_probe");
    let mut reference = allowed_payload(&lane);
    reference["guard_payload_ref"] = json!("ref");
    assert_eq!(
        deferred(&run(&lane, reference)),
        "direct_hook_payload_unsupported"
    );
    // Codex PermissionRequest is the no-decision passthrough. A harness
    // without that passthrough still defers, and the command is not judged.
    let mut permission = allowed_payload(&lane);
    permission["hook_event_name"] = json!("PermissionRequest");
    assert_eq!(
        deferred(&run_as(&lane, "copilot", Some(HOME), permission)),
        "direct_hook_event_unsupported"
    );
    let mut environment = allowed_payload(&lane);
    environment["guard_execution_environment"] = json!("PATH=/bin");
    assert_eq!(
        deferred(&run(&lane, environment)),
        "direct_hook_execution_environment_invalid"
    );
    let mut homeless = allowed_payload(&lane);
    homeless.as_object_mut().unwrap().remove("cwd");
    assert_eq!(
        deferred(&run(&lane, homeless)),
        "direct_hook_workspace_missing"
    );
    let mut elsewhere = allowed_payload(&lane);
    elsewhere["cwd"] = json!(lane.fixture.root.to_str().unwrap());
    // An overlay keeps the unbound directory waiting for its own publish.
    fs::write(lane.fixture.root.join(".hol-guard.toml"), b"").unwrap();
    assert_eq!(
        deferred(&run(&lane, elsewhere)),
        DirectLaneDefer::WorkspaceUnknown.code()
    );
    assert_eq!(
        deferred(&run(&lane, json!(["not", "an", "object"]))),
        "direct_hook_payload_unsupported"
    );
}

#[test]
fn other_harnesses_and_homes_defer() {
    let lane = lane("harness", json!({}));
    let mut request = HookDirectRequestV1 {
        harness: "gemini".to_owned(),
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        home_dir: Some(HOME.to_owned()),
        workspace: None,
        deadline_budget_ms: None,
        payload: allowed_payload(&lane),
    };
    let result: Value =
        serde_json::from_slice(&evaluate(request.clone(), &lane.fixture.store).unwrap()).unwrap();
    assert_eq!(deferred(&result), "direct_hook_harness_unsupported");
    request.harness = "codex".to_owned();
    request.home_dir = Some("/home/other".to_owned());
    let result: Value =
        serde_json::from_slice(&evaluate(request, &lane.fixture.store).unwrap()).unwrap();
    assert_eq!(deferred(&result), "direct_hook_home_mismatch");
}

#[test]
fn daemon_only_state_in_the_binding_defers() {
    // The daemon checks custom rules only against an allow floor, and this
    // fixture policy warns on commands.
    let rules = lane("rules", json!({ "local_cli_block_rules": true }));
    assert_eq!(run(&rules, allowed_payload(&rules))["outcome"], "answer");
    for (label, missing) in [
        ("no-home", "home_dir"),
        ("no-postures", "harness_postures"),
        ("no-rules", "local_cli_block_rules"),
    ] {
        let lane = lane(label, json!({}));
        let mut bound = binding(&lane.fixture, &lane.workspace);
        bound["home_dir"] = json!(HOME);
        bound["harness_postures"] = json!({});
        bound["local_cli_block_rules"] = json!(false);
        bound["evidence_drain"] = json!(true);
        bound.as_object_mut().unwrap().remove(missing);
        push(&lane.fixture, Some(bound)).unwrap();
        assert_eq!(
            deferred(&run(&lane, allowed_payload(&lane))),
            "direct_hook_binding_incomplete",
            "{missing}"
        );
    }
}

/// A package script run in `lane`'s workspace: a command that launches a
/// local CLI a custom rule can name.
fn package_script_payload(lane: &Lane) -> Value {
    fs::write(
        std::path::Path::new(&lane.workspace).join("package.json"),
        br#"{"name": "demo", "scripts": {"build": "tsc"}}"#,
    )
    .unwrap();
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "npm run build" },
        "cwd": lane.workspace,
    })
}

#[test]
fn custom_rules_still_answer_a_command_that_launches_no_local_cli() {
    let rules = allowing_lane("cli-rules", json!({ "local_cli_block_rules": true }));
    // `pwd` launches no local CLI, so no custom rule can block it.
    assert_eq!(run(&rules, allowed_payload(&rules))["outcome"], "answer");
    // The edge reviews a launch it cannot prove benign, so the daemon
    // renders that verdict whether or not a rule names the CLI.
    assert_eq!(
        deferred(&run(&rules, package_script_payload(&rules))),
        "direct_hook_not_allow"
    );
}

#[test]
fn a_block_rule_saved_after_the_publish_still_answers_a_command_without_a_cli() {
    let lane = allowing_lane("stored-rules", json!({}));
    let store = lane.fixture.root.join("guard.db");
    let connection = rusqlite::Connection::open(&store).unwrap();
    connection
        .execute_batch(
            "create table local_cli_grant (cli_id text primary key, state text not null);
             create table local_cli_command_grant (
                 cli_id text not null, command_id text not null, state text not null
             );
             insert into local_cli_grant values ('cli', 'allowed');
             insert into local_cli_command_grant values ('cli', 'run', 'allow');",
        )
        .unwrap();
    assert_eq!(run(&lane, allowed_payload(&lane))["outcome"], "answer");
    for statement in [
        "update local_cli_command_grant set state = 'block'",
        "update local_cli_command_grant set state = 'allow'; \
         update local_cli_grant set state = 'blocked'",
    ] {
        connection.execute_batch(statement).unwrap();
        assert_eq!(
            run(&lane, allowed_payload(&lane))["outcome"],
            "answer",
            "{statement}"
        );
    }
    drop(connection);
    // A store the resident cannot read counts as holding rules.
    fs::write(&store, b"not a database").unwrap();
    assert_eq!(
        deferred(&run(&lane, allowed_payload(&lane))),
        "direct_hook_local_cli_rules"
    );
}

#[test]
fn a_hook_for_an_app_guard_does_not_protect_defers() {
    let lane = lane("unmanaged", json!({}));
    let connection = rusqlite::Connection::open(lane.fixture.root.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table managed_installs (
                 harness text primary key, active integer not null, workspace text,
                 manifest_json text not null, updated_at text not null
             );",
        )
        .unwrap();
    let unmanaged = "direct_hook_harness_unmanaged";
    // No install recorded anywhere: the daemon reviews the hook.
    assert_ne!(run(&lane, allowed_payload(&lane))["reason"], unmanaged);
    for (statement, expected_unmanaged) in [
        // Only another app is protected, so Codex hooks are leftovers.
        (
            "insert into managed_installs values ('claude-code', 1, null, '{}', 'now')",
            true,
        ),
        (
            "insert into managed_installs values ('codex', 1, null, '{}', 'now')",
            false,
        ),
        (
            "update managed_installs set active = 0 where harness = 'codex'",
            true,
        ),
        // Its own inactive row decides even with no other app protected.
        (
            "update managed_installs set active = 0 where harness = 'claude-code'",
            true,
        ),
    ] {
        connection.execute_batch(statement).unwrap();
        let result = run(&lane, allowed_payload(&lane));
        assert_eq!(
            result["reason"] == unmanaged,
            expected_unmanaged,
            "{statement}: {result}"
        );
    }
}

#[test]
fn an_edge_verdict_other_than_allow_takes_the_daemon_path() {
    // A sensitive read needs review, so the resident evaluates it and still
    // hands it to the daemon.
    let lane = lane("verdict", json!({}));
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "toolName": "read_file",
        "toolInput": { "file_path": ".env.synthetic" },
        "cwd": lane.workspace,
    });
    assert_eq!(deferred(&run(&lane, payload)), "direct_hook_not_allow");
}

#[test]
fn every_verdict_in_watch_is_answered() {
    // Watch records a call it would have stopped and lets it run, so the
    // daemon returns the edge's non-blocking response for every verdict.
    let sensitive_read = |lane: &Lane| {
        json!({
            "hook_event_name": "PreToolUse",
            "toolName": "read_file",
            "toolInput": { "file_path": ".env.synthetic" },
            "cwd": lane.workspace,
        })
    };
    let watch = lane("watch", json!({ "harness_postures": { "codex": "watch" } }));
    let result = run(&watch, sensitive_read(&watch));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_ne!(result["edge"]["result"]["minimum_action"], "allow");
    let page = drain(&watch, None);
    let record = &page["records"][0];
    assert_eq!(record["event"], "PreToolUse");
    assert_eq!(
        record["harness_response"],
        result["edge"]["harness_response"]
    );

    // The posture of the harness that sent the hook decides.
    let other = lane(
        "watch-other",
        json!({ "harness_postures": { "claude-code": "watch" } }),
    );
    assert_eq!(
        deferred(&run(&other, sensitive_read(&other))),
        "direct_hook_not_allow"
    );
}

#[test]
fn a_command_the_policy_warns_on_is_answered() {
    // The fixture policy warns on commands: the daemon would record the
    // warning and let the command run, so the resident answers it.
    let lane = lane("warned", json!({}));
    let result = run(&lane, allowed_payload(&lane));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(result["edge"]["result"]["decision"], "allow");
    assert_eq!(result["edge"]["result"]["minimum_action"], "warn");
    assert_eq!(drain(&lane, None)["records"].as_array().unwrap().len(), 1);
}

#[test]
fn a_cursor_pre_tool_use_is_answered_only_as_its_client_renders_it() {
    let cursor = lane("cursor", json!({}));
    let result = run_as(&cursor, "cursor", Some(HOME), allowed_payload(&cursor));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(result["edge"]["harness_response"]["policy_action"], "warn");
    assert_eq!(drain(&cursor, None)["records"][0]["harness"], "cursor");
    let sensitive_read = |lane: &Lane| {
        json!({
            "hook_event_name": "PreToolUse",
            "toolName": "read_file",
            "toolInput": { "file_path": ".env.synthetic" },
            "cwd": lane.workspace,
        })
    };
    assert_eq!(
        deferred(&run_as(
            &cursor,
            "cursor",
            Some(HOME),
            sensitive_read(&cursor)
        )),
        "direct_hook_not_allow"
    );
    // A review the binding cannot queue still takes the daemon path, as any
    // harness's does. Watch lets the call run, so the Cursor client allows
    // whatever the edge would have stopped.
    let watch = lane(
        "cursor-watch",
        json!({ "harness_postures": { "cursor": "watch" } }),
    );
    let result = run_as(&watch, "cursor", Some(HOME), sensitive_read(&watch));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(result["edge"]["harness_response"]["policy_action"], "warn");
}

#[test]
fn a_cursor_verdict_is_answered_only_as_the_daemon_returns_it() {
    let cursor_edge = |decision: &str, minimum_action: &str, code: Value, rendered: &str| {
        serde_json::to_vec(&json!({
            "schema": "guard-hook-edge-result.v2",
            "event_name": "PreToolUse",
            "result": {
                "decision": decision,
                "minimum_action": minimum_action,
                "reason_code": code,
            },
            "harness_response": { "policy_action": rendered },
        }))
        .unwrap()
    };
    let answered = |decision, minimum_action, code, rendered, recording_only| {
        cursor::answer(
            &cursor_edge(decision, minimum_action, code, rendered),
            recording_only,
        )
        .is_ok()
    };
    let repairable = json!(REPAIRABLE_BLOCK_REASON);
    for (decision, minimum_action, rendered) in [
        ("allow", "allow", "allow"),
        ("allow", "warn", "warn"),
        ("deny", "block", "block"),
        ("block", "block", "block"),
        ("deny", "sandbox-required", "block"),
        ("deny", "sandbox-required", "sandbox-required"),
    ] {
        assert!(
            answered(decision, minimum_action, json!(null), rendered, false),
            "{decision} {minimum_action} {rendered}"
        );
    }
    // The daemon repairs an authority block and pauses a review, and the
    // client renders only what the edge rendered.
    for (decision, minimum_action, code, rendered) in [
        ("deny", "block", repairable.clone(), "block"),
        ("deny", "review", json!(null), "block"),
        ("deny", "require-reapproval", json!(null), "block"),
        ("allow", "block", json!(null), "block"),
        ("deny", "warn", json!(null), "block"),
        ("deny", "block", json!(null), "review"),
        ("deny", "block", json!(null), "allow"),
        ("allow", "allow", json!(null), "block"),
    ] {
        assert!(
            !answered(decision, minimum_action, code, rendered, false),
            "{decision} {minimum_action} {rendered}"
        );
    }
    // Watch answers whatever the edge let run, and nothing it stopped.
    assert!(answered("deny", "block", json!(null), "warn", true));
    assert!(answered("deny", "block", repairable, "allow", true));
    assert!(!answered("deny", "block", json!(null), "block", true));
}

/// The next evidence page, after acknowledging `acked`, a page drained before.
fn drain(lane: &Lane, acked: Option<&Value>) -> Value {
    let request = crate::hook_direct_evidence::HookDirectEvidenceDrainRequestV1 {
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        max_records: None,
        ack_through: acked.and_then(|page| page["through"].as_u64()),
        ack_epoch: acked.and_then(|page| page["epoch"].as_str().map(str::to_owned)),
    };
    let page =
        crate::hook_direct_evidence::drain(&request, lane.fixture.store.direct_evidence()).unwrap();
    serde_json::from_slice(&page).unwrap()
}

#[test]
fn a_daemon_that_does_not_drain_evidence_keeps_the_lane_closed() {
    let lane = lane("undrained", json!({ "evidence_drain": false }));
    assert_eq!(
        deferred(&run(&lane, allowed_payload(&lane))),
        "direct_hook_evidence_undrained"
    );
    assert_eq!(drain(&lane, None)["records"], json!([]));
}

#[test]
fn an_answer_queues_the_evidence_the_daemon_records() {
    let lane = allowing_lane("evidence", json!({}));
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "toolName": "read_file",
        "toolInput": { "file_path": "README.md" },
        "cwd": lane.workspace,
    });
    payload["hook_env"] = json!({ "HOME": HOME });
    let result = run(&lane, payload);
    assert_eq!(result["outcome"], "answer", "{result}");
    let edge = &result["edge"];
    let page = drain(&lane, None);
    let records = page["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["event"], "PreToolUse");
    assert_eq!(record["harness"], "codex");
    assert_eq!(record["workspace"], json!(lane.workspace));
    assert_eq!(record["home_dir"], HOME);
    assert_eq!(record["harness_response"], edge["harness_response"]);
    assert_eq!(
        record["receipt"],
        edge.get("receipt").cloned().unwrap_or(Value::Null)
    );
    let mut expected = json!({
        "hook_event_name": "PreToolUse",
        "toolName": "read_file",
        "toolInput": { "file_path": "README.md" },
        "cwd": lane.workspace,
    });
    expected["guard_execution_environment"] = Value::Null;
    assert_eq!(record["payload"], expected);
    let again = drain(&lane, None);
    assert_eq!(again["records"], page["records"]);
    assert_eq!(drain(&lane, Some(&page))["records"], json!([]));
}

#[test]
fn a_deferred_hook_queues_no_evidence() {
    let lane = lane("deferred-evidence", json!({}));
    let mut permission = allowed_payload(&lane);
    permission["hook_event_name"] = json!("PermissionRequest");
    // Copilot has no passthrough, so this stays a defer and records nothing.
    deferred(&run_as(&lane, "copilot", Some(HOME), permission));
    assert_eq!(drain(&lane, None)["records"], json!([]));
}

#[test]
fn a_bounded_harness_hook_is_answered_as_codex_is() {
    let answered = allowing_lane("bounded", json!({}));
    let result = run_as(&answered, "kimi", Some(HOME), allowed_payload(&answered));
    assert_eq!(result["outcome"], "answer", "{result}");
    let page = drain(&answered, None);
    let record = &page["records"][0];
    assert_eq!(record["harness"], "kimi");
    assert_eq!(
        record["harness_response"],
        result["edge"]["harness_response"]
    );
    // A ZCode allow passes the daemon's containment step unchanged.
    let zcode = allowing_lane("bounded-zcode", json!({}));
    let result = run_as(&zcode, "zcode", Some(HOME), allowed_payload(&zcode));
    assert_eq!(result["outcome"], "answer", "{result}");
    let page = drain(&zcode, None);
    assert_eq!(page["records"][0]["harness"], "zcode");
    assert_eq!(
        page["records"][0]["harness_response"],
        result["edge"]["harness_response"]
    );
    let grok = allowing_lane("bounded-grok", json!({}));
    let result = run_as(&grok, "grok", Some(HOME), allowed_payload(&grok));
    assert_eq!(result["outcome"], "answer", "{result}");
    let page = drain(&grok, None);
    assert_eq!(page["records"][0]["harness"], "grok");
    assert_eq!(
        page["records"][0]["harness_response"],
        result["edge"]["harness_response"]
    );
}

#[test]
fn a_claude_code_hook_answers_with_the_daemon_home_it_left_out() {
    let answered = allowing_lane("claude-code", json!({}));
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "toolName": "read_file",
        "toolInput": { "file_path": "README.md" },
        "cwd": answered.workspace,
    });
    payload["hook_env"] = json!({ "HOME": HOME });
    let result = run_as(&answered, "claude-code", None, payload);
    assert_eq!(result["outcome"], "answer", "{result}");
    let page = drain(&answered, None);
    let record = &page["records"][0];
    assert_eq!(record["harness"], "claude-code");
    assert_eq!(record["home_dir"], HOME);
    assert_eq!(
        deferred(&run_as(
            &answered,
            "claude-code",
            Some("/home/other"),
            allowed_payload(&answered)
        )),
        "direct_hook_home_mismatch"
    );

    // Watch answers a Claude Code hook as well.
    let watch = allowing_lane(
        "claude-code-watch",
        json!({ "harness_postures": { "claude-code": "watch" } }),
    );
    let result = run_as(&watch, "claude-code", None, allowed_payload(&watch));
    assert_eq!(result["outcome"], "answer", "{result}");
    let codex_read = json!({
        "hook_event_name": "PreToolUse",
        "toolName": "read_file",
        "toolInput": { "file_path": "README.md" },
        "cwd": watch.workspace,
    });
    assert_eq!(run(&watch, codex_read)["outcome"], "answer");

    // Without a bound home there is none to stand in for the daemon's.
    let homeless = lane("claude-code-homeless", json!({}));
    let mut bound = binding(&homeless.fixture, &homeless.workspace);
    bound["harness_postures"] = json!({});
    bound["local_cli_block_rules"] = json!(false);
    bound["evidence_drain"] = json!(true);
    push(&homeless.fixture, Some(bound)).unwrap();
    assert_eq!(
        deferred(&run_as(
            &homeless,
            "claude-code",
            None,
            allowed_payload(&homeless)
        )),
        "direct_hook_binding_incomplete"
    );
}

/// A shell command that already ran.
fn post_tool_payload(lane: &Lane) -> Value {
    json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "pwd" },
        "tool_response": { "stdout": "/repo", "exit_code": 0 },
        "cwd": lane.workspace,
    })
}

#[test]
fn a_post_tool_use_is_answered_where_the_daemon_only_records_it() {
    // Watch and local block rules change only how the daemon answers a
    // `PreToolUse`; it returns every reviewed `PostToolUse` unchanged.
    for (label, extra) in [
        ("post", json!({})),
        (
            "post-watch",
            json!({ "harness_postures": { "codex": "watch" } }),
        ),
        ("post-rules", json!({ "local_cli_block_rules": true })),
    ] {
        let lane = lane(label, extra);
        let result = run(&lane, post_tool_payload(&lane));
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        assert_eq!(result["edge"]["event_name"], "PostToolUse", "{label}");
        let page = drain(&lane, None);
        let records = page["records"].as_array().unwrap();
        assert_eq!(records.len(), 1, "{label}");
        assert_eq!(records[0]["event"], "PostToolUse", "{label}");
        assert_eq!(
            records[0]["harness_response"], result["edge"]["harness_response"],
            "{label}"
        );
    }
    let watch = lane(
        "post-claude-watch",
        json!({ "harness_postures": { "claude-code": "watch" } }),
    );
    let result = run_as(&watch, "claude-code", None, post_tool_payload(&watch));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(drain(&watch, None)["records"][0]["harness"], "claude-code");
}

#[test]
fn a_prompt_answer_needs_its_receipt() {
    let reviewed = |receipt: Value| {
        serde_json::to_vec(&json!({
            "schema": "guard-hook-edge-result.v2",
            "event_name": "UserPromptSubmit",
            "result": { "decision": "block", "minimum_action": "block" },
            "harness_response": {},
            "receipt": receipt,
        }))
        .unwrap()
    };
    assert!(prompt_answer(&reviewed(json!({ "decision_id": "d" })), false).is_ok());
    assert_eq!(
        prompt_answer(&reviewed(Value::Null), false),
        Err(HookDirectDefer::EdgeFailed)
    );
    assert_eq!(
        prompt_answer(&post_edge(json!({})), false),
        Err(HookDirectDefer::EdgeFailed)
    );
}

#[test]
fn only_a_prompt_the_daemon_restyles_carries_its_notice() {
    let reviewed = |action: &str| {
        serde_json::to_vec(&json!({
            "schema": "guard-hook-edge-result.v2",
            "event_name": "UserPromptSubmit",
            "result": {
                "decision": "block",
                "minimum_action": action,
                "reason": "Synthetic prompt reason",
            },
            "harness_response": { "hookSpecificOutput": { "hookEventName": "UserPromptSubmit" } },
            "receipt": { "decision_id": "d" },
        }))
        .unwrap()
    };
    for action in ["require-reapproval", "block", "sandbox-required"] {
        let noticed = prompt_answer(&reviewed(action), true).unwrap();
        assert!(
            noticed["harness_response"]["systemMessage"].is_string(),
            "{action}: {noticed}"
        );
        let plain = prompt_answer(&reviewed(action), false).unwrap();
        assert!(
            plain["harness_response"].get("systemMessage").is_none(),
            "{action}"
        );
    }
    let briefed = prompt_answer(&reviewed("require-reapproval"), true).unwrap();
    assert!(briefed["harness_response"]["hookSpecificOutput"]["additionalContext"].is_string());
    for action in ["allow", "warn", "review", ""] {
        let answered = prompt_answer(&reviewed(action), true).unwrap();
        assert!(
            answered["harness_response"].get("systemMessage").is_none(),
            "{action}"
        );
    }
}

fn prompt_payload(lane: &Lane) -> Value {
    json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "List the files in this repository.",
        "cwd": lane.workspace,
    })
}

#[test]
fn a_codex_prompt_is_answered_in_either_posture() {
    for (label, extra) in [
        ("prompt", json!({})),
        (
            "prompt-watch",
            json!({ "harness_postures": { "codex": "watch" } }),
        ),
        ("prompt-rules", json!({ "local_cli_block_rules": true })),
    ] {
        let reviewed = lane(label, extra);
        let result = run(&reviewed, prompt_payload(&reviewed));
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        assert_eq!(result["edge"]["event_name"], "UserPromptSubmit", "{label}");
        let page = drain(&reviewed, None);
        let record = &page["records"][0];
        assert_eq!(record["event"], "UserPromptSubmit", "{label}");
        assert_eq!(record["receipt"], result["edge"]["receipt"], "{label}");
    }
}

#[test]
fn a_claude_code_prompt_without_a_notice_is_answered_in_either_posture() {
    for (label, extra) in [
        ("prompt-claude", json!({})),
        (
            "prompt-claude-watch",
            json!({ "harness_postures": { "claude-code": "watch" } }),
        ),
    ] {
        let reviewed = lane(label, extra);
        let result = run_as(&reviewed, "claude-code", None, prompt_payload(&reviewed));
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        let page = drain(&reviewed, None);
        assert_eq!(page["records"][0]["harness"], "claude-code", "{label}");
    }
}

#[path = "hook_direct_lifecycle_tests.rs"]
mod lifecycle;

#[path = "hook_direct_counters_evaluate_tests.rs"]
mod counters;

#[path = "hook_direct_pi_tests.rs"]
mod pi_lane;

#[path = "hook_direct_cursor_tests.rs"]
mod cursor_observer;
