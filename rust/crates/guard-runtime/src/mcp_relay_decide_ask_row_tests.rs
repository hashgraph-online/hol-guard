//! What the queued row carries: the item, the queue arguments, the artifact
//! facts a tool call never has and the bounded-grant hint.

use super::*;
use crate::mcp_tool_policy_decision::Current;

fn request() -> McpRelayDecideRequestV1 {
    serde_json::from_value(json!({
        "guard_home": "/guard",
        "hash_workspace": "/work",
        "build": {
            "harness": "opencode",
            "server_name": "browser",
            "tool_name": "navigate",
            "source_scope": "project",
            "config_path": "/work/opencode.json",
            "transport": "stdio",
            "server_id": null,
            "server_fingerprint": null,
            "server_identity": null,
            "provider_catalog_hash": null,
            "tool": {"kind": "catalog", "entry": null},
        },
        "arguments": {"format": "mapping", "entries": [["url", "https://example.test/"]]},
        "launcher_home": "/home/user",
        "cwd": "/work",
        "catalog_state": "present",
        "params": {"name": "navigate", "arguments": {"url": "https://example.test/"}},
    }))
    .unwrap()
}

fn artifact() -> McpToolCallArtifactV1 {
    McpToolCallArtifactV1 {
        artifact_id: "opencode:project:browser:navigate".to_owned(),
        name: "browser:navigate".to_owned(),
        harness: "opencode".to_owned(),
        source_scope: "project".to_owned(),
        config_path: "/work/opencode.json".to_owned(),
        command: Some("npx browser-mcp".to_owned()),
        transport: Some("stdio".to_owned()),
        publisher: None,
        metadata: Map::new(),
    }
}

fn decision(source: &str) -> Decision {
    Decision::plain(Current {
        action: GuardAction::RequireReapproval,
        source: source.to_owned(),
        signals: vec!["Opens an external site.".to_owned()],
        summary: "browser navigation".to_owned(),
        risk_categories: vec!["browser_navigation".to_owned()],
    })
}

fn projection(browser_intent: Option<Value>) -> Projection {
    Projection {
        launch_target: "example.test".to_owned(),
        risk_summary: "Navigates the browser to example.test".to_owned(),
        browser_intent,
    }
}

fn intent(categories: Value) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert(
        "browser_intent".to_owned(),
        json!({
            "intent": "browser.navigation",
            "mcp_server_name": "browser",
            "mcp_server_identity_hash": "a".repeat(64),
            "target_domain": "example.test",
            "target_origin": "https://example.test",
            "risk_categories": categories,
        }),
    );
    row
}

#[test]
fn the_review_item_carries_the_projection_and_the_decision_signals() {
    let artifact = artifact();
    let decision = decision("approval-gate");
    let item = review_item(
        &artifact,
        "sha256:token",
        &decision.signals,
        &projection(None),
        "require-reapproval",
        &decision,
    );
    assert_eq!(item["artifact_id"], json!(artifact.artifact_id));
    assert_eq!(item["artifact_type"], json!("tool_call"));
    assert_eq!(item["artifact_hash"], json!("sha256:token"));
    assert_eq!(item["config_path"], json!(artifact.config_path));
    assert_eq!(item["changed_fields"], json!(["runtime_tool_call"]));
    assert_eq!(item["launch_target"], json!("example.test"));
    assert_eq!(
        item["risk_signals"],
        json!(["Opens an external site.".to_owned()])
    );
    // A decision reached without a normalization or a reuse carries none.
    assert!(!item.contains_key("scanner_evidence"));
    assert!(!item.contains_key("browser_intent"));

    let browser = json!({"intent": "browser.navigation"});
    let item = review_item(
        &artifact,
        "sha256:token",
        &decision.signals,
        &projection(Some(browser.clone())),
        "review",
        &decision,
    );
    assert_eq!(
        item["changed_fields"],
        json!(["runtime_tool_call", "runtime_browser_tool_call"])
    );
    assert_eq!(item["browser_intent"], browser);
    assert_eq!(item["policy_action"], json!("review"));
}

#[test]
fn the_scanner_evidence_names_how_the_action_was_reached() {
    let mut normalized = decision("approval-gate");
    normalized.normalization_reason_code = Some("unknown_action".to_owned());
    normalized.original_action = Some("escalate".to_owned());
    let evidence = scanner_evidence(&normalized);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0]["source"], json!("guard_action_normalizer"));
    assert_eq!(evidence[0]["original_action"], json!("escalate"));

    let mut reused = normalized;
    reused.approval_reuse_status = Some("expired");
    reused.approval_reuse_reason_code = Some("approval_expired".to_owned());
    reused.current_action = Some(GuardAction::RequireReapproval);
    reused.saved_action = Some(GuardAction::Allow);
    let evidence = scanner_evidence(&reused);
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[1]["source"], json!("approval_reuse"));
    assert_eq!(evidence[1]["status"], json!("expired"));
    assert_eq!(evidence[1]["saved_action"], json!("allow"));
}

#[test]
fn the_queued_artifact_carries_no_command_facts_a_tool_call_never_has() {
    let artifact = artifact();
    let queued = queue_artifact(&artifact);
    for key in QUEUE_METADATA_KEYS {
        assert_eq!(queued[key], Value::Null, "{key}");
    }
    // `artifact_risk_summary` and `artifact_risk_signals` of an artifact
    // whose metadata holds neither.
    assert_eq!(queued["risk_summary"], Value::Null);
    assert_eq!(queued["risk_signals"], json!([]));
    let wire = &queued["wire"];
    assert_eq!(wire["harness"], json!("opencode"));
    assert_eq!(wire["artifact_type"], json!("tool_call"));
    assert_eq!(wire["command"], json!("npx browser-mcp"));
    assert_eq!(wire["transport"], json!("stdio"));
    assert_eq!(wire["publisher"], Value::Null);
    assert_eq!(wire["metadata"], json!({"mcp_tool_identity": true}));
}

#[test]
fn the_queue_arguments_offer_no_continuation_and_name_this_build() {
    let request = request();
    let artifact = artifact();
    let args = args(
        &request,
        Map::new(),
        &artifact,
        "http://127.0.0.1:8787",
        "2026-10-15T00:00:00+00:00",
        "full",
    );
    assert_eq!(args["harness"], json!("opencode"));
    assert_eq!(args["approval_center_url"], json!("http://127.0.0.1:8787"));
    assert_eq!(args["prompt_shown"], json!(true));
    assert_eq!(args["redaction_level"], json!("full"));
    assert_eq!(args["cwd"], json!("/work"));
    // The build-injected version, which `_current_guard_version` reports.
    assert_eq!(args["guard_version"], json!(crate::PACKAGE_VERSION));
    assert_eq!(
        args["artifacts"][artifact.artifact_id.as_str()]["wire"]["artifact_id"],
        json!(artifact.artifact_id)
    );
    let continuation = &args["continuation"];
    assert_eq!(continuation["harness"], json!("opencode"));
    assert_eq!(continuation["original_hook_attached"], json!(false));
    assert_eq!(continuation["wait_deadline"], Value::Null);
    assert_eq!(continuation["session_target_verified"], json!(false));
    assert_eq!(continuation["correlation_candidates"], json!([null, null]));
}

#[test]
fn the_temporary_grant_hint_follows_the_intent_the_row_carries() {
    let row = intent(json!(["browser_navigation", "browser_external_domain"]));
    let hint = temporary_mcp_approval(&row).expect("eligible");
    assert_eq!(hint["version"], json!(1));
    assert_eq!(hint["eligible"], json!(true));
    assert_eq!(hint["category"], json!("browser_navigation"));
    assert_eq!(hint["server_name"], json!("browser"));
    assert_eq!(hint["target_label"], json!("example.test"));
    assert_eq!(hint["allowed_durations"], json!(GRANT_DURATIONS));
    assert_eq!(hint["allowed_targets"], json!(GRANT_TARGETS));

    // A category the intent does not claim, and a hard exclusion beside it.
    assert_eq!(temporary_mcp_approval(&intent(json!([]))), None);
    assert_eq!(
        temporary_mcp_approval(&intent(json!(["browser_navigation", "secret_access"]))),
        None
    );
    // A row of a call that is not a browser intent at all.
    assert_eq!(temporary_mcp_approval(&Map::new()), None);
}
