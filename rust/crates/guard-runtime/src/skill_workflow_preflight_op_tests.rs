use super::*;
use guard_contracts::{SkillDependenciesInputV1, SkillPreflightInputV1};
use serde_json::json;

fn empty() -> SkillWorkflowPreflightRequestV1 {
    SkillWorkflowPreflightRequestV1 {
        schema: SKILL_WORKFLOW_PREFLIGHT_REQUEST_SCHEMA.to_owned(),
        request_id: "preflight-1".to_owned(),
        subop: "dependencies".to_owned(),
        dependencies: None,
        preflight: None,
    }
}

fn declaring(text: Option<&str>) -> SkillWorkflowPreflightRequestV1 {
    SkillWorkflowPreflightRequestV1 {
        dependencies: Some(SkillDependenciesInputV1 {
            present: text.is_some(),
            text: text.map(str::to_owned),
        }),
        ..empty()
    }
}

fn resolving(dependencies: Value, connections: Vec<Value>) -> SkillWorkflowPreflightRequestV1 {
    SkillWorkflowPreflightRequestV1 {
        subop: "preflight".to_owned(),
        preflight: Some(SkillPreflightInputV1 {
            dependencies,
            connections,
            authority_revision: 9,
        }),
        ..empty()
    }
}

fn run(request: &SkillWorkflowPreflightRequestV1) -> SkillWorkflowPreflightResultV1 {
    let bytes = evaluate_skill_workflow_preflight_request(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn a_declaration_is_read_through_the_op() {
    let manifest = json!({
        "schema_version": "guard.skill-dependencies.v1",
        "tools": [{"connection_id": "local-cli.alpha", "tool_name": "run"}],
    })
    .to_string();
    let result = run(&declaring(Some(&manifest)));
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    assert_eq!(
        result.payload.expect("payload")["tools"],
        json!([{"connection_id": "local-cli.alpha", "tool_name": "run"}])
    );
}

#[test]
fn a_skill_that_declares_nothing_is_not_a_skill_whose_declaration_failed() {
    let absent = run(&declaring(None)).payload.expect("payload");
    assert_eq!(absent["status"], "absent");
    let unreadable = run(&SkillWorkflowPreflightRequestV1 {
        dependencies: Some(SkillDependenciesInputV1 {
            present: true,
            text: None,
        }),
        ..empty()
    })
    .payload
    .expect("payload");
    assert_eq!(unreadable["status"], "invalid");
}

#[test]
fn a_declared_provider_action_is_reviewed_through_the_composio_contract() {
    let dependencies = json!({
        "source": "guard-extension",
        "status": "declared",
        "tools": [{
            "connection_id": "local-cli.alpha",
            "tool_name": "mcp__codex_apps__composio__composio_multi_execute_tool",
        }],
    });
    let connections = vec![json!({
        "cli_id": "local-cli.alpha",
        "identity_hash": "hash-alpha",
        "state": "allowed",
        "stale": false,
        "commands": [{
            "usage": "mcp__codex_apps__composio__composio_multi_execute_tool",
            "state": "allow",
        }],
    })];
    let payload = run(&resolving(dependencies, connections))
        .payload
        .expect("payload");
    assert_eq!(payload["requirements"][0]["state"], "ask");
    assert_eq!(
        payload["requirements"][0]["reason"],
        "provider-account-and-action-unverified"
    );
    assert_eq!(payload["authority_revision"], 9);
    assert_eq!(payload["permissions_granted"], false);
    assert_eq!(payload["runtime_checks_required"], true);
}

#[test]
fn a_request_without_its_input_answers_nothing_rather_than_an_empty_declaration() {
    for subop in ["dependencies", "preflight"] {
        let result = run(&SkillWorkflowPreflightRequestV1 {
            subop: subop.to_owned(),
            ..empty()
        });
        assert_eq!(result.status, "error", "{subop}");
        assert_eq!(result.code, "native_skill_workflow_preflight_missing_input");
        assert!(result.payload.is_none());
    }
}

#[test]
fn an_unknown_subop_is_refused() {
    let result = run(&SkillWorkflowPreflightRequestV1 {
        subop: "grant".to_owned(),
        ..empty()
    });
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_skill_workflow_preflight_unknown_subop");
    assert!(result.payload.is_none());
}

#[test]
fn a_request_the_op_cannot_read_answers_nothing() {
    let result = run(&SkillWorkflowPreflightRequestV1 {
        schema: "guard-skill-workflow-preflight-request.v0".to_owned(),
        ..declaring(Some(
            r#"{"schema_version": "guard.skill-dependencies.v1", "tools": []}"#,
        ))
    });
    assert_eq!(result.status, "error");
    assert_eq!(
        result.code,
        "native_skill_workflow_preflight_schema_mismatch"
    );
    assert!(result.payload.is_none());
}

#[test]
fn the_result_binds_the_request_that_produced_it() {
    let result = run(&declaring(Some("{}")));
    assert_eq!(result.schema, SKILL_WORKFLOW_PREFLIGHT_RESULT_SCHEMA);
    assert_eq!(result.request_id, "preflight-1");
    assert!(result.request_sha256.starts_with("sha256:"));
    let other = run(&declaring(Some("[]")));
    assert_ne!(result.request_sha256, other.request_sha256);
}
