//! Saved decisions answered from a local store that other tables share.

use super::*;

/// `answer_with` in a store `seed` changed first.
pub(super) fn answer_in(
    tag: &str,
    action: &str,
    answering: &DirectLaneBinding,
    seed: &str,
) -> Result<Value, HookDirectDefer> {
    let vectors = vectors();
    let workspace = workspace(tag);
    let full = binding();
    let (edge, payload, artifact_id, token) = bound_request(&full, &workspace);
    let (path, connection) = local_store(tag);
    insert_decision(
        &connection,
        "claude-code",
        &artifact_id,
        &token,
        action,
        "approval-gate",
    );
    connection.execute_batch(seed).unwrap();
    let guard_home = path.parent().unwrap().to_str().unwrap().to_owned();
    answer(
        &edge,
        &Context {
            harness: "claude-code",
            payload: &payload,
            recorded_payload: &payload,
            workspace: &workspace,
            home_dir: vectors["home_dir"].as_str().unwrap(),
            guard_home: &guard_home,
            binding: answering,
        },
    )
}

#[test]
fn custom_grants_leave_a_review_that_launches_no_local_cli_to_its_saved_decision() {
    // The daemon reads a custom grant only for a command that launches a
    // local CLI, and this `Read` names no command.
    let seed = "create table local_cli_grant (cli_id text, state text);
                insert into local_cli_grant values ('cli', 'blocked');";
    let answered = answer_in("answer-grants", "allow", &binding(), seed).unwrap();
    let response = &answered["harness_response"];
    assert_eq!(response["approval_reuse_status"], json!("accepted"));
}
