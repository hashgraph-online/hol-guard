//! An edge `PreToolUse` answer queues its activity only when the daemon
//! returns that answer as the edge rendered it.

use serde_json::json;

use super::*;

/// `answered`'s allowed `pwd`, a shell action asking for its activity, with
/// the daemon's exact-command lookup and containment settled as an unrouted
/// call's are.
fn settled(home: &Path) -> (GuardHookEnvelopeV2, GuardHookEdgeResultV2) {
    let (mut envelope, mut edge) = answered(home, true);
    envelope.record_pre_tool_activity = true;
    edge.result["action"]["action_type"] = json!("command");
    edge.exact_command_block = Some(false);
    edge.containment_route = Some("none".to_owned());
    edge.containment_rewrite = None;
    (envelope, edge)
}

fn recorded(home: &Path, envelope: &GuardHookEnvelopeV2, edge: GuardHookEdgeResultV2) -> bool {
    let answer = encoded(envelope, true, edge);
    assert_eq!(answer["receipt_recorded"], json!(true));
    answer.get("activity_recorded") == Some(&json!(true)) && activities_accepted(home) == json!(2)
}

#[test]
fn a_pre_tool_edge_the_daemon_returns_as_rendered_queues_its_activity() {
    let home = store_home("edge-pre-activity-recorded");
    start_writer(&home);
    let (envelope, edge) = settled(&home);
    assert!(recorded(&home, &envelope, edge));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_sink_route_the_edge_kept_is_returned_as_rendered() {
    let home = store_home("edge-pre-activity-kept");
    start_writer(&home);
    let (envelope, mut edge) = settled(&home);
    edge.containment_route = Some("sink".to_owned());
    edge.containment_rewrite = Some("kept".to_owned());
    assert!(recorded(&home, &envelope, edge));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_edge_leaves_a_pre_tool_activity_the_daemon_may_change_to_the_daemon() {
    let home = store_home("edge-pre-activity-unsettled");
    start_writer(&home);
    type Change = fn(&mut GuardHookEnvelopeV2, &mut GuardHookEdgeResultV2);
    let changes: [(&str, Change); 6] = [
        ("unasked", |envelope, _| {
            envelope.record_pre_tool_activity = false
        }),
        ("approval pause", |_, edge| {
            edge.result["minimum_action"] = json!("review");
        }),
        ("exact lookup", |_, edge| edge.exact_command_block = None),
        ("saved block", |_, edge| {
            edge.exact_command_block = Some(true)
        }),
        ("sink rewrite", |_, edge| {
            edge.containment_route = Some("sink".to_owned());
        }),
        ("routed sink", |_, edge| {
            edge.containment_route = Some("sink".to_owned());
            edge.containment_rewrite = Some("routed".to_owned());
        }),
    ];
    for (name, change) in changes {
        let (mut envelope, mut edge) = settled(&home);
        change(&mut envelope, &mut edge);
        let answer = encoded(&envelope, true, edge);
        assert_eq!(answer["receipt_recorded"], json!(true), "{name}");
        assert!(answer.get("activity_recorded").is_none(), "{name}");
    }
    // Only the writer's starting activity was recorded.
    assert_eq!(activities_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_recorded_only_call_or_a_custom_block_records_the_answer_the_daemon_returns() {
    let (mut envelope, mut edge) = settled(&store_home("edge-pre-activity-response"));
    // The daemon's exact-command lookup and a pause both wait on these.
    edge.exact_command_block = None;
    edge.result["minimum_action"] = json!("review");
    envelope.recording_only = true;
    assert_eq!(
        daemon_response(&envelope, &edge),
        edge.harness_response.as_ref()
    );
    envelope.recording_only = false;
    assert_eq!(daemon_response(&envelope, &edge), None);
    edge.result["minimum_action"] = json!("allow");
    let block = json!({"policy_action": "block", "prompted": false});
    edge.local_cli_rule = Some(guard_contracts::GuardHookLocalCliRuleV1 {
        blocked: true,
        harness_response: block.clone(),
    });
    assert_eq!(daemon_response(&envelope, &edge), Some(&block));
    // A non-shell action never reaches the daemon's exact-command lookup.
    edge.local_cli_rule = None;
    edge.result["action"]["action_type"] = json!("file_read");
    assert_eq!(
        daemon_response(&envelope, &edge),
        edge.harness_response.as_ref()
    );
}

#[test]
fn a_response_the_activity_cannot_take_is_not_recorded() {
    for response in [
        json!({"policy_action": 1}),
        json!({"approval_reuse_status": false}),
    ] {
        assert!(PreToolActivity::of(response.as_object().unwrap()).is_none());
    }
    let activity = PreToolActivity::of(
        json!({"policy_action": "allow", "prompted": true})
            .as_object()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(activity.policy_action.as_deref(), Some("allow"));
    assert!(activity.prompted);
    assert_eq!(activity.approval_reuse_status, "not-applicable");
}

#[test]
fn the_resident_advertises_that_its_edge_records_pre_tool_activity() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&EDGE_PRE_TOOL_ACTIVITY_RECORD_FEATURE));
}
