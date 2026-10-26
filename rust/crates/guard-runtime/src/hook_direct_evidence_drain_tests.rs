use super::{
    allowed_payload, allowing_lane, deferred, drain, lane, post_tool_payload, run, run_as, HOME,
};
use crate::policy_store::policy_store_direct_lane::tests::{binding, push};
use serde_json::{json, Value};

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
    // Kimi has no passthrough, so this stays a defer and records nothing.
    deferred(&run_as(&lane, "kimi", Some(HOME), permission));
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
