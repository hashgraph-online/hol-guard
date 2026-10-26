//! The package-shaped approval row a queued request is written with, against
//! the `ask` branch of `_queue_package_approval_response`.

use guard_command::effect_decision::GuardAction as EffectAction;

use super::*;
use crate::mcp_tool_policy_decision::Current;

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

/// A package-request artifact, which carries the request summaries the
/// `artifact_risk` derivation reads and none of the command metadata a tool
/// call's queued artifact entry states.
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
        metadata: json!({
            "request_summary": "npm install left-pad",
            "runtime_request_summary": "Installs left-pad from npm",
            "runtime_request_reason": "package_request",
            "runtime_request_signals": ["install"],
            // Neither wire carries this one, and `_queue_artifact` never
            // reads it either.
            "inspection_notes": "ignored",
        }),
        runtime_private_metadata: Value::Null,
    }
}

fn decision() -> Decision {
    Decision::plain(Current {
        action: EffectAction::Review,
        source: "policy".to_owned(),
        signals: vec!["left-pad has an advisory".to_owned()],
        summary: "installs a package".to_owned(),
        risk_categories: Vec::new(),
    })
}

/// The lane's own answer for the queued route, as `answered` leaves it.
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
    evaluation.insert(
        "user_copy".to_owned(),
        json!({
            "title": "Package request needs review",
            "summary": "left-pad has a known advisory",
            "harness_message": "Approve the request, then retry.",
        }),
    );
    PackageAnswer {
        block: None,
        policy_action: "review".to_owned(),
        decision_source: ask::APPROVAL_PENDING_SOURCE.to_owned(),
        decision: DECISION_LABEL.to_owned(),
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

#[test]
fn the_queued_item_states_the_package_request_rather_than_the_tool_call() {
    let answer = answer();
    let item = review_item(
        &request(),
        &artifact(),
        &answer,
        GuardAction::Review,
        &decision(),
    )
    .expect("the item is built");
    assert_eq!(item["artifact_id"], json!(artifact().artifact_id));
    assert_eq!(item["artifact_name"], json!("left-pad"));
    assert_eq!(item["artifact_hash"], json!(answer.artifact_hash));
    // The package request's own type, and both fields it changed.
    assert_eq!(item["artifact_type"], json!("package_request"));
    assert_eq!(
        item["changed_fields"],
        json!(["runtime_tool_call", "package_request"])
    );
    assert_eq!(item["policy_action"], json!("review"));
    // The evaluation's summary, not the projected risk a tool call's row
    // carries, and the reason signals alone beside it.
    assert_eq!(item["risk_summary"], json!("left-pad has a known advisory"));
    assert_eq!(item["risk_signals"], json!(["left-pad has an advisory"]));
    assert_eq!(
        item["supply_chain_evaluation"],
        Value::Object(answer.evaluation.clone())
    );
}

#[test]
fn the_queued_item_leads_its_evidence_with_the_tool_decisions_own() {
    let item = review_item(
        &request(),
        &artifact(),
        &answer(),
        GuardAction::Review,
        &decision(),
    )
    .expect("the item is built");
    // `_package_scanner_evidence`: the tool half, then the package half the
    // lane held for the receipt.
    let mut expected = ask_row::scanner_evidence(&decision());
    expected.push(json!({"kind": "package_execution_context"}));
    assert_eq!(item["scanner_evidence"], Value::Array(expected));
}

#[test]
fn the_queued_item_states_every_field_the_package_evaluation_queues() {
    let item = review_item(
        &request(),
        &artifact(),
        &answer(),
        GuardAction::Review,
        &decision(),
    )
    .expect("the item is built");
    assert_eq!(
        item.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "artifact_hash",
            "artifact_id",
            "artifact_name",
            "artifact_type",
            "changed_fields",
            "config_path",
            "decision_v2_json",
            "launch_target",
            "policy_action",
            "risk_signals",
            "risk_summary",
            "scanner_evidence",
            "source_scope",
            "supply_chain_evaluation",
        ],
    );
    // `self._call_projector.project(tool_name, params).launch_target`, which
    // Python reads without checking, so a call that names no target queues
    // the empty string rather than deferring as a tool call's row does.
    assert!(item["launch_target"].is_string());
}

#[test]
fn the_decision_v2_carries_the_evaluations_user_copy_over_its_own_text() {
    let decided = decision_v2(&answer(), GuardAction::Review).expect("the decision is built");
    assert_eq!(decided["user_title"], json!("Package request needs review"));
    assert_eq!(decided["user_body"], json!("left-pad has a known advisory"));
    assert_eq!(
        decided["harness_message"],
        json!("Approve the request, then retry.")
    );
    assert_eq!(
        decided["dashboard_primary_detail"],
        json!("left-pad has a known advisory")
    );
    // The reasons' own V2 signals, which `build_decision_v2` composed it from.
    assert_eq!(
        decided["signals"][0]["signal_id"],
        json!("supply-chain.advisory")
    );
}

#[test]
fn an_evaluation_with_no_user_copy_writes_the_nulls_python_writes() {
    let mut answer = answer();
    answer.evaluation.remove("user_copy");
    let decided = decision_v2(&answer, GuardAction::Review).expect("the decision is built");
    for key in ["user_title", "user_body", "harness_message"] {
        assert_eq!(decided[key], Value::Null);
    }
}

#[test]
fn the_queued_artifact_entry_carries_the_package_requests_real_risk_facts() {
    let queued = queue_artifact(&artifact()).expect("the artifact entry is built");
    // `_QUEUE_METADATA_KEYS`, which a package request never carries.
    for key in QUEUE_METADATA_KEYS {
        assert_eq!(queued[key], Value::Null);
    }
    // Unlike a tool call's entry, the derivation has a command summary to read.
    assert_eq!(queued["risk_summary"], json!("Installs left-pad from npm"));
    assert!(queued["risk_signals"].is_array());
}

#[test]
fn the_two_wires_carry_the_two_metadata_sets_their_readers_accept() {
    let artifact = artifact();
    let wire = wire_artifact(&artifact);
    // `consumer.projection.wire_artifact`: the full launch definition, with
    // the metadata narrowed to the keys the capability logic reads.
    assert_eq!(wire["artifact_id"], json!(artifact.artifact_id));
    assert_eq!(wire["harness"], json!("codex"));
    assert_eq!(wire["args"], json!(["install", "left-pad"]));
    assert_eq!(
        wire["metadata"],
        json!({
            "request_summary": "npm install left-pad",
            "runtime_request_summary": "Installs left-pad from npm",
        })
    );
    // `risk._wire_artifact`: the five fields `artifact_risk` accepts, which
    // rejects anything else, with its own metadata keys.
    let risk = risk_wire(&artifact);
    assert_eq!(
        risk.as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["args", "command", "metadata", "name", "url"],
    );
    assert_eq!(
        risk["metadata"],
        json!({
            "request_summary": "npm install left-pad",
            "runtime_request_reason": "package_request",
            "runtime_request_signals": ["install"],
            "runtime_request_summary": "Installs left-pad from npm",
        })
    );
}
