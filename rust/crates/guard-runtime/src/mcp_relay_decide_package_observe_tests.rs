//! The observed approval requests a forwarded package call is queued with,
//! against the `observe_forward` branch of `_handle_package_request`.

use super::*;
use crate::mcp_tool_policy_decision::{Current, Decision};
use guard_command::effect_decision::GuardAction as EffectAction;
use guard_contracts::{McpToolCallArtifactV1, McpToolCallIdentityPayloadV1};

const TOOL: &str = "install_package";

fn request() -> McpRelayDecideRequestV1 {
    serde_json::from_value(json!({
        "guard_home": "/guard",
        "hash_workspace": "/work",
        "build": {
            "harness": "codex",
            "server_name": "registry",
            "tool_name": TOOL,
            "source_scope": "project",
            "config_path": "/work/.codex/config.toml",
            "transport": "stdio",
            "server_id": null,
            "server_fingerprint": null,
            "server_identity": null,
            "provider_catalog_hash": null,
            "tool": {"kind": "catalog", "entry": null},
        },
        "arguments": {"format": "mapping", "entries": [["command", "npm install left-pad"]]},
        "path": "/usr/bin:/bin",
        "launcher_home": "/home/user",
        "cwd": "/work",
        "catalog_state": "present",
        "params": {"name": TOOL, "arguments": {"command": "npm install left-pad"}},
    }))
    .unwrap()
}

/// The package request the call resolved, as the lane holds it.
fn artifact() -> GuardArtifact {
    GuardArtifact {
        artifact_id: "package-request:npm:left-pad".to_owned(),
        name: "left-pad".to_owned(),
        harness: "codex".to_owned(),
        artifact_type: "package_request".to_owned(),
        source_scope: "project".to_owned(),
        config_path: "/work/.codex/config.toml".to_owned(),
        command: Some("npm".to_owned()),
        args: vec!["install".to_owned(), "left-pad".to_owned()],
        url: None,
        transport: None,
        publisher: None,
        metadata: json!({"request_summary": "npm install left-pad"}),
        runtime_private_metadata: Value::Null,
    }
}

/// The tool call's own resolution, whose decision the observed tool row states
/// the risk facts of. `Decision::plain` reaches its action by neither
/// normalization nor approval reuse, so it leaves no scanner evidence.
fn resolved(artifact_hash: Option<&str>) -> Resolved {
    Resolved {
        identity: McpToolCallIdentityPayloadV1 {
            artifact: McpToolCallArtifactV1 {
                artifact_id: "codex:project:install_package".to_owned(),
                name: TOOL.to_owned(),
                harness: "codex".to_owned(),
                source_scope: "project".to_owned(),
                config_path: "/work/.codex/config.toml".to_owned(),
                command: None,
                transport: Some("stdio".to_owned()),
                publisher: None,
                metadata: Map::new(),
            },
            runtime_private_metadata: Map::new(),
            artifact_hash: artifact_hash.map(ToOwned::to_owned),
            risk_categories: Vec::new(),
        },
        decision: Decision::plain(Current {
            action: EffectAction::Review,
            source: "policy".to_owned(),
            signals: vec!["installs from a public registry".to_owned()],
            summary: "installs a package".to_owned(),
            risk_categories: Vec::new(),
        }),
        mode: "observe".to_owned(),
        redaction_level: Some("partial".to_owned()),
    }
}

/// The lane's own answer for the forward the observation is written beside.
fn answer() -> PackageAnswer {
    let mut evaluation = Map::new();
    evaluation.insert("decision".to_owned(), json!("review"));
    evaluation.insert(
        "risk_summary".to_owned(),
        json!("left-pad has a known advisory"),
    );
    evaluation.insert(
        "reasons".to_owned(),
        json!([{"code": "advisory", "message": "left-pad has an advisory"}]),
    );
    PackageAnswer {
        block: None,
        policy_action: "allow".to_owned(),
        decision_source: OBSERVE_SOURCE.to_owned(),
        decision: "allow".to_owned(),
        signals: vec!["left-pad has an advisory".to_owned()],
        policy_workspace: Some("package-request-workspace:v2:abc".to_owned()),
        artifact_hash: "guard-approval-context:v1:abc".to_owned(),
        evaluation,
        evidence: vec![json!({"kind": "package_execution_context"})],
        redaction_level: None,
        approval: None,
        observed_notices: Vec::new(),
    }
}

/// The composition's own `observe_forward` answer.
fn composed(tool: Value, package: Value) -> Value {
    json!({
        "kind": "observe_forward",
        "executed_action": "allow",
        "observe_override": true,
        "observed_policy_action": "review",
        "observed_tool_policy_action": "review",
        "observed_package_policy_action": "review",
        "queue_observed_tool": tool,
        "queue_observed_package": package,
        "evidence_append": [{"source": "observe_mode"}],
    })
}

#[test]
fn the_observation_names_the_executed_action_and_both_rows_to_queue() {
    let observed = observed(&composed(json!("review"), json!("require-reapproval")))
        .expect("the composition answered a forward this port can write");

    // The call is forwarded under the action the policies permitted, and each
    // row is written for the action that policy would have stopped it with.
    assert_eq!(observed.executed_action, "allow");
    assert_eq!(observed.tool.as_deref(), Some("review"));
    assert_eq!(observed.package.as_deref(), Some("require-reapproval"));
    assert_eq!(
        observed.evidence_append,
        vec![json!({"source": "observe_mode"})]
    );
}

#[test]
fn a_policy_that_permitted_the_call_queues_no_row_of_its_own() {
    // `(!permitted(action)).then(...)`: a permitted policy answers `None`,
    // which is an observation with nothing to write rather than a refusal.
    let observed =
        observed(&composed(Value::Null, json!("review"))).expect("the forward is still observed");

    assert_eq!(observed.tool, None);
    assert_eq!(observed.package.as_deref(), Some("review"));
}

#[test]
fn an_observed_action_this_port_cannot_read_defers_the_call() {
    assert_eq!(
        observed(&composed(json!(["review"]), Value::Null)),
        Err(PACKAGE_OBSERVE_UNSUPPORTED)
    );
}

#[test]
fn an_observation_missing_the_action_it_forwards_under_defers_the_call() {
    let mut answer = composed(Value::Null, Value::Null);
    answer.as_object_mut().unwrap().remove("executed_action");

    assert_eq!(observed(&answer), Err(PACKAGE_OBSERVE_UNSUPPORTED));
}

#[test]
fn an_observation_missing_its_evidence_defers_the_call() {
    // The evidence the override is recorded with is the only account of what
    // the enforced policy would have done, so a forward without it is not the
    // one the proxy writes.
    let mut answer = composed(Value::Null, Value::Null);
    answer.as_object_mut().unwrap().remove("evidence_append");

    assert_eq!(observed(&answer), Err(PACKAGE_OBSERVE_UNSUPPORTED));
}

#[test]
fn a_row_the_store_would_drop_unqueued_is_never_written() {
    // `queue_blocked_approvals` queues only a reviewable action. A terminal
    // one is answered as a terminal leg before the forward is composed, so an
    // action that reaches the write is one this port cannot account for.
    assert_eq!(
        write(&request(), "oauth", "block", Map::new()),
        Err(PACKAGE_OBSERVE_UNSUPPORTED)
    );
}

#[test]
fn the_tool_row_states_the_fresh_decisions_own_risk_facts() {
    let item = tool_item(
        &request(),
        &resolved(Some("guard-approval-context:v1:tool")),
        "review",
    )
    .expect("the row is built");

    assert_eq!(item["artifact_id"], json!("codex:project:install_package"));
    assert_eq!(item["artifact_name"], json!(TOOL));
    assert_eq!(
        item["artifact_hash"],
        json!("guard-approval-context:v1:tool")
    );
    assert_eq!(item["artifact_type"], json!("tool_call"));
    assert_eq!(item["changed_fields"], json!(["runtime_tool_call"]));
    assert_eq!(item["policy_action"], json!("review"));
    // The decision's own summary and signals, not the projected risk the
    // `ask` lane's row falls back to.
    assert_eq!(item["risk_summary"], json!("installs a package"));
    assert_eq!(
        item["risk_signals"],
        json!(["installs from a public registry"])
    );
}

#[test]
fn the_tool_row_carries_its_scanner_evidence_even_when_there_is_none() {
    // `extra_fields={"scanner_evidence": list(fresh_tool_evidence)}`: the key
    // is passed whether or not the decision left any, unlike the `ask` row.
    let item = tool_item(
        &request(),
        &resolved(Some("guard-approval-context:v1:tool")),
        "review",
    )
    .expect("the row is built");

    assert_eq!(item["scanner_evidence"], json!([]));
}

#[test]
fn a_tool_call_with_no_approval_context_defers_the_call() {
    assert_eq!(
        tool_item(&request(), &resolved(None), "review"),
        Err(PACKAGE_OBSERVE_UNSUPPORTED)
    );
}

#[test]
fn the_package_row_states_the_evaluations_own_facts_against_the_request() {
    let answer = answer();
    let item = package_item(
        &request(),
        &resolved(Some("guard-approval-context:v1:tool")),
        &artifact(),
        &answer,
        "review",
    )
    .expect("the row is built");

    assert_eq!(item["artifact_id"], json!(artifact().artifact_id));
    assert_eq!(item["artifact_type"], json!("package_request"));
    assert_eq!(
        item["changed_fields"],
        json!(["runtime_tool_call", "package_request"])
    );
    // The request's own approval-context token, not the tool call's.
    assert_eq!(item["artifact_hash"], json!(answer.artifact_hash));
    assert_eq!(item["risk_summary"], json!("left-pad has a known advisory"));
    assert_eq!(item["risk_signals"], json!(answer.signals));
    assert_eq!(
        item["supply_chain_evaluation"],
        Value::Object(answer.evaluation.clone())
    );
    assert!(item.contains_key("decision_v2_json"));
}

#[test]
fn the_package_row_carries_the_evidence_half_the_lane_held() {
    // `_package_scanner_evidence`: the tool half first, then the package half
    // the lane held for the receipt. This decision reached its action by
    // neither normalization nor approval reuse, so its half is empty and the
    // package half is the whole of it.
    let item = package_item(
        &request(),
        &resolved(Some("guard-approval-context:v1:tool")),
        &artifact(),
        &answer(),
        "review",
    )
    .expect("the row is built");

    assert_eq!(
        item["scanner_evidence"],
        json!([{"kind": "package_execution_context"}])
    );
}

#[test]
fn a_package_action_the_decision_wire_cannot_name_defers_the_call() {
    assert_eq!(
        package_item(
            &request(),
            &resolved(Some("guard-approval-context:v1:tool")),
            &artifact(),
            &answer(),
            "escalate",
        ),
        Err(PACKAGE_OBSERVE_UNSUPPORTED)
    );
}
