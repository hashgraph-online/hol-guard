//! What one answered package call leaves for the drain, against the receipts
//! `_record_package_block` and `_record_package_forward` write.

use guard_command::effect_decision::GuardAction;
use guard_command::package_execution_context::PackageExecutionContext;

use super::*;
use crate::mcp_tool_policy_decision::Current;

const TOOL: &str = "install_package";

/// A decide request for `TOOL`, as the relay received it.
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
        "catalog_state": "present",
        "params": {"name": TOOL, "arguments": {"command": "npm install left-pad"}},
    }))
    .unwrap()
}

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
        metadata: json!({}),
        runtime_private_metadata: Value::Null,
    }
}

fn context() -> PackageExecutionContext {
    PackageExecutionContext {
        digest: "ctx".to_owned(),
        portable: true,
        components: Vec::new(),
        non_portable_reason: None,
    }
}

fn decision() -> Decision {
    Decision::plain(Current {
        action: GuardAction::Allow,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: "installs a package".to_owned(),
        risk_categories: Vec::new(),
    })
}

/// One answered call, stopped when `block` is set.
fn answer(block: Option<(String, Value)>, policy_action: &str) -> PackageAnswer {
    let mut evaluation = Map::new();
    evaluation.insert("decision".to_owned(), json!(policy_action));
    PackageAnswer {
        block,
        policy_action: policy_action.to_owned(),
        decision_source: format!("policy-{policy_action}"),
        decision: format!("package-{policy_action}"),
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

/// A resolved policy whose evaluation reported `reasons`.
fn policy(reasons: Value) -> PackagePolicy {
    let mut evaluation = Map::new();
    evaluation.insert("reasons".to_owned(), reasons);
    PackagePolicy {
        evaluation,
        current_action: GuardAction::Review,
        artifact_hash: "guard-approval-context:v1:abc".to_owned(),
        policy_workspace: None,
        execution_context: context(),
        reused_decision: None,
        claim_disposition: None,
    }
}

#[test]
fn a_forwarded_package_call_records_the_policy_workspace_it_ran_under() {
    let request = request();
    let identity = json!({"artifact_hash": "tool-hash"});
    let answer = answer(None, "warn");
    let record = record(
        &request,
        &identity,
        &decision(),
        &artifact(),
        "/work",
        &answer,
    )
    .expect("the record is built");
    assert_eq!(record["kind"], json!(PACKAGE_CALL_EVIDENCE_KIND));
    assert_eq!(record["harness"], json!("codex"));
    assert_eq!(record["outcome"], json!("forward"));
    assert_eq!(record["decision_source"], json!("policy-warn"));
    assert_eq!(record["policy_action"], json!("warn"));
    assert_eq!(record["tool_name"], json!(TOOL));
    assert_eq!(record["params"], request.params);
    // The host's own key order, which the receipt projects the arguments from.
    assert_eq!(
        record["arguments"]["entries"],
        json!([["command", "npm install left-pad"]])
    );
    assert_eq!(record["identity"], identity);
    assert_eq!(record["decision"], decision().to_value());
    let package = &record["package"];
    assert_eq!(package["artifact_id"], json!(artifact().artifact_id));
    assert_eq!(package["artifact_hash"], json!(answer.artifact_hash));
    // The workspace and `PATH` the drain rebuilds the package artifact under.
    assert_eq!(package["workspace"], json!("/work"));
    assert_eq!(package["path"], json!("/usr/bin:/bin"));
    assert_eq!(package["evaluation"], json!({"decision": "warn"}));
    assert_eq!(package["evidence"], json!(answer.evidence));
    assert_eq!(package["signals"], json!(answer.signals));
    assert_eq!(
        package["policy_workspace"],
        json!("package-request-workspace:v2:abc")
    );
}

#[test]
fn a_stopped_package_call_records_no_policy_workspace() {
    // `_record_package_block` passes `block_tool_call` no policy workspace, so
    // the record states none for the drain to write.
    let answer = answer(Some(("blocked".to_owned(), json!({}))), "block");
    let record = record(
        &request(),
        &json!({}),
        &decision(),
        &artifact(),
        "/work",
        &answer,
    )
    .expect("the record is built");
    assert_eq!(record["outcome"], json!("block"));
    assert_eq!(record["package"].get("policy_workspace"), None);
    assert_eq!(
        record["package"]["artifact_hash"],
        json!(answer.artifact_hash)
    );
}

#[test]
fn a_queued_package_request_records_the_inbox_row_it_leaves() {
    // Only the safe-alternative queue route carries a redaction level, and
    // the drain writes `record_unprompted_review` from it.
    let mut queued = answer(Some(("blocked".to_owned(), json!({}))), "review");
    queued.redaction_level = Some("partial".to_owned());
    let reviewed = record(
        &request(),
        &json!({}),
        &decision(),
        &artifact(),
        "/work",
        &queued,
    )
    .expect("the record is built");
    assert_eq!(reviewed["review"], json!({"redaction_level": "partial"}));
    // Every other route leaves none, and the drain rejects a row on one.
    let forwarded = record(
        &request(),
        &json!({}),
        &decision(),
        &artifact(),
        "/work",
        &answer(None, "warn"),
    )
    .expect("the record is built");
    assert_eq!(forwarded.get("review"), None);
}

/// The gate parses with no `PATH` when the request carries none, and the
/// record says so rather than leaving the drain its own.
#[test]
fn a_call_relayed_without_a_search_path_records_none() {
    for path in [None, Some(String::new())] {
        let mut request = request();
        request.path = path.clone();
        let record = record(
            &request,
            &json!({}),
            &decision(),
            &artifact(),
            "/work",
            &answer(None, "warn"),
        )
        .expect("the record is built");
        assert_eq!(record["package"]["path"], Value::Null, "{path:?}");
    }
}

#[test]
fn the_receipt_evidence_is_the_execution_context_then_each_reused_approval() {
    let recorded = evidence(&policy(json!([
        {"code": "advisory"},
        {"code": "saved_allow", "approval_reuse": {"status": "reused", "request_id": "r1"}},
        {"code": "stale", "approval_reuse": "not-a-mapping"},
        {"code": "saved_block", "approval_reuse": {"status": "blocked"}},
    ])));
    assert_eq!(recorded.len(), 3);
    assert_eq!(recorded[0], context().to_evidence());
    assert_eq!(
        recorded[1],
        json!({"source": "approval_reuse", "status": "reused", "request_id": "r1"})
    );
    assert_eq!(
        recorded[2],
        json!({"source": "approval_reuse", "status": "blocked"})
    );
    // An evaluation with no reasons reports the context alone.
    let mut empty = policy(json!([]));
    empty.evaluation.remove("reasons");
    assert_eq!(evidence(&empty), vec![context().to_evidence()]);
}
