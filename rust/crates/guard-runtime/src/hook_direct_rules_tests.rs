use super::{
    allowed_payload, allowing_lane, deferred, drain, lane, package_script_payload, run, run_as,
    Lane, HOME,
};
use crate::hook_direct::{cursor, REPAIRABLE_BLOCK_REASON};
use serde_json::{json, Value};
use std::fs;

#[test]
fn custom_rules_still_answer_a_command_that_launches_no_local_cli() {
    let rules = allowing_lane("cli-rules", json!({ "local_cli_block_rules": true }));
    // `pwd` launches no local CLI, so no custom rule can block it.
    assert_eq!(run(&rules, allowed_payload(&rules))["outcome"], "answer");
    // The edge reviews a launch it cannot prove benign, so the daemon
    // renders that verdict whether or not a rule names the CLI. A `tsc`
    // build script gets no narrow build receipt, and the hook carries no
    // execution environment to prove the workspace sandbox with, so macOS
    // keeps the review too.
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
