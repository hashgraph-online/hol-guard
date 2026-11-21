use super::{allowing_lane, deferred, run, run_as, HOME};
use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use serde_json::json;

#[test]
fn evaluate_counts_each_answer_and_defer_under_its_harness() {
    let lane = allowing_lane("counters", json!({}));
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "toolName": "read_file",
        "toolInput": { "file_path": "README.md" },
        "cwd": lane.workspace,
    });
    payload["hook_env"] = json!({ "HOME": HOME });
    assert_eq!(run(&lane, payload)["outcome"], "answer");
    let elsewhere = payload_elsewhere(&lane);
    // An overlay keeps the unbound directory waiting for its own publish.
    std::fs::write(lane.fixture.root.join(".hol-guard.toml"), b"").unwrap();
    assert_eq!(
        deferred(&run(&lane, elsewhere.clone())),
        DirectLaneDefer::WorkspaceUnknown.code()
    );
    assert_eq!(
        deferred(&run_as(&lane, "gemini", Some(HOME), elsewhere)),
        "direct_hook_harness_unsupported"
    );
    assert_eq!(
        lane.fixture.store.direct_evidence().counters().snapshot(),
        json!({ "by_harness": {
            "codex": { "answer": 1, "direct_lane_workspace_unknown": 1 },
            "other": { "direct_hook_harness_unsupported": 1 },
        }})
    );
}

fn payload_elsewhere(lane: &super::Lane) -> serde_json::Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "pwd" },
        "cwd": lane.fixture.root.to_str().unwrap(),
    })
}
