use super::*;
use crate::hook_direct::saved_decision::{exact_command_block_response, Context};
use guard_command::hook_responses::Object;

#[test]
fn an_exact_command_block_is_rendered_by_the_resident() {
    let (store_path, connection) = local_store("exact-command-block");
    let command = "cat src/a.py";
    let candidates = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
        command: Some(command),
        artifact_type: Some("shell_command"),
        artifact_id: None,
        artifact_name: None,
        harness: None,
    });
    let artifact_id = candidates.exact_artifact_ids.first().unwrap().clone();
    insert_decision(
        &connection,
        "claude-code",
        &artifact_id,
        None,
        "block",
        "approval-gate",
    );
    let workspace = workspace("exact-command-block");
    let payload = serde_json::json!({
        "tool_input": {"command": command},
        "cwd": workspace,
    })
    .as_object()
    .unwrap()
    .clone();
    let binding = binding();
    let guard_home = store_path.parent().unwrap().to_str().unwrap().to_owned();
    let context = Context {
        harness: "claude-code",
        payload: &payload,
        recorded_payload: &payload,
        workspace: &workspace,
        home_dir: "/tmp",
        guard_home: &guard_home,
        binding: &binding,
        hint: None,
    };
    let result = serde_json::from_value::<Object>(serde_json::json!({
        "decision": "allow",
        "minimum_action": "review",
        "policy_action": "review",
        "action": {"action_type": "shell"},
    }))
    .unwrap();
    let response = exact_command_block_response(&context, &result)
        .unwrap()
        .expect("saved block response");
    assert_eq!(response["approval_reuse_status"], "blocked");
    assert_eq!(response["policy_action"], "block");
    assert_eq!(response["reason_code"], "saved_exact_command_block");
}
