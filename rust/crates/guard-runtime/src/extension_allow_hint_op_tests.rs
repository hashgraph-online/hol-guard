use super::*;
use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::EXTENSION_ALLOW_HINT_FEATURE;
use serde_json::json;

const DOCKER_PERMISSION: &str = "command.container-runtime.permission.docker-sensitive";
const HARD_RESET_PERMISSION: &str = "command.git.permission.hard-reset";
const DOCKER: &str = "docker version --format '{{.Server.Version}}'";
const HARD_RESET: &str = "git reset --hard HEAD~1";

fn admitted_controls(name: &str) -> CompiledNativeCommandControls {
    let home = std::env::temp_dir().join(format!(
        "guard-extension-allow-hint-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    crate::contributed_mcp_catalog_test_support::controls_for(&home, false, &[], &[])
}

/// A query built from the same evidence the native pre-tool evaluator produces.
fn query(controls: &CompiledNativeCommandControls, command: &str) -> ExtensionAllowHintQueryV1 {
    let model = parse_command(&CommandModelRequestV1 {
        command: command.into(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "guard-shell".into(),
    })
    .unwrap();
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(controls),
        None,
        Default::default(),
        None,
    );
    let mut evidence = serde_json::to_value(result).unwrap();
    evidence["command_model"] = serde_json::to_value(&model).unwrap();
    ExtensionAllowHintQueryV1 {
        kind: EXTENSION_ALLOW_HINT_QUERY_KIND.into(),
        command_text: command.into(),
        canonical_command: serde_json::to_value(&model).unwrap(),
        native_extension_evidence: evidence,
        control_snapshot: serde_json::to_value(controls.control_binding()).unwrap(),
        cwd: None,
        home_dir: None,
        reduction_budget_ms: None,
    }
}

fn request(query: ExtensionAllowHintQueryV1) -> ExtensionAllowHintRequestV1 {
    ExtensionAllowHintRequestV1 {
        schema: EXTENSION_ALLOW_HINT_REQUEST_SCHEMA.into(),
        request_id: "allow-hint-test".into(),
        query,
    }
}

fn answer(
    request: &ExtensionAllowHintRequestV1,
    controls: &CompiledNativeCommandControls,
) -> ExtensionAllowHintResultV1 {
    let bytes = evaluate_extension_allow_hint(request, Some(controls)).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn hint_for(
    controls: &CompiledNativeCommandControls,
    command: &str,
) -> Option<ExtensionAllowHintV1> {
    let result = answer(&request(query(controls, command)), controls);
    assert_eq!(result.status, "ok", "{command}: {}", result.code);
    let payload = result.payload.expect("an ok answer carries a payload");
    assert_eq!(payload.kind, EXTENSION_ALLOW_HINT_QUERY_KIND);
    payload.hint
}

#[test]
fn docker_sensitive_review_names_the_container_runtime_permission() {
    let controls = admitted_controls("docker");
    let hint = hint_for(&controls, DOCKER).expect("docker-sensitive review has a hint");
    assert_eq!(hint.schema, EXTENSION_ALLOW_HINT_SCHEMA);
    assert_eq!(hint.permission_ids, [DOCKER_PERMISSION]);
    assert_eq!(
        hint.rule_ids,
        ["command.container-runtime.docker-sensitive"]
    );
    assert_eq!(hint.extension_ids, ["command.container-runtime"]);
    assert!(hint.relied_permission_ids.is_empty());
    assert_eq!(
        hint.catalog_digest,
        controls.command_catalog().unwrap().catalog_digest
    );
}

#[test]
fn destructive_git_permission_is_still_hinted() {
    let controls = admitted_controls("hard-reset");
    let hint = hint_for(&controls, HARD_RESET).expect("hard reset review has a hint");
    assert_eq!(hint.permission_ids, [HARD_RESET_PERMISSION]);
    assert_eq!(hint.extension_ids, ["command.git"]);
}

#[test]
fn compound_review_names_each_gating_permission_once() {
    let controls = admitted_controls("compound");
    let command = format!("{DOCKER} && {HARD_RESET}");
    let unbounded = hint_for(&controls, &command).expect("compound review has a hint");
    let mut permissions = unbounded.permission_ids.clone();
    permissions.sort();
    assert_eq!(permissions, [DOCKER_PERMISSION, HARD_RESET_PERMISSION]);
    assert_eq!(unbounded.rule_ids.len(), 2);
    assert_eq!(unbounded.extension_ids.len(), 2);

    // A spent reduction budget answers the verified full set unchanged.
    let mut bounded = query(&controls, &command);
    bounded.reduction_budget_ms = Some(0);
    let result = answer(&request(bounded), &controls);
    assert_eq!(result.payload.unwrap().hint, Some(unbounded));
}

#[test]
fn an_allowed_command_has_no_hint() {
    let controls = admitted_controls("allowed");
    assert_eq!(hint_for(&controls, "git status"), None);
}

#[test]
fn a_fixed_pretool_floor_has_no_hint() {
    let controls = admitted_controls("floor");
    let mut blocked = query(&controls, DOCKER);
    blocked.native_extension_evidence["minimum_action"] = json!("block");
    let mut other_reason = query(&controls, DOCKER);
    other_reason.native_extension_evidence["reason_code"] = json!("native_sensitive_access_review");
    let mut no_reason = query(&controls, DOCKER);
    no_reason
        .native_extension_evidence
        .as_object_mut()
        .unwrap()
        .remove("reason_code");
    for mutated in [blocked, other_reason, no_reason] {
        let result = answer(&request(mutated), &controls);
        assert!(result.payload.and_then(|payload| payload.hint).is_none());
    }
}

#[test]
fn only_a_native_review_is_an_extension_review() {
    let review = json!({"minimum_action":"review","reason_code":EXTENSION_REVIEW_REASON});
    assert!(is_extension_review(&review));
    assert!(is_extension_review(&json!("not an object")));
    assert!(!is_extension_review(&json!({
        "minimum_action":"block","reason_code":EXTENSION_REVIEW_REASON
    })));
    assert!(!is_extension_review(&json!({
        "minimum_action":"review","reason_code":"native_command_extension_review"
    })));
    assert!(!is_extension_review(&json!({"minimum_action":"review"})));
}

#[test]
fn a_foreign_schema_or_kind_is_a_bound_error() {
    let controls = admitted_controls("schema");
    let mut wrong_schema = request(query(&controls, DOCKER));
    wrong_schema.schema = "bogus".into();
    let result = answer(&wrong_schema, &controls);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_extension_allow_hint_schema_mismatch");
    assert!(result.payload.is_none());

    let mut wrong_kind = request(query(&controls, DOCKER));
    wrong_kind.query.kind = "other".into();
    let result = answer(&wrong_kind, &controls);
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_extension_allow_hint_kind_invalid");
}

#[test]
fn the_answer_is_bound_to_its_request() {
    let controls = admitted_controls("binding");
    let asked = request(query(&controls, DOCKER));
    let result = answer(&asked, &controls);
    assert_eq!(result.schema, EXTENSION_ALLOW_HINT_RESULT_SCHEMA);
    assert_eq!(result.request_id, "allow-hint-test");
    assert_eq!(
        result.request_sha256,
        request_digest_with_limit(&asked, EXTENSION_ALLOW_HINT_MAX_BYTES).unwrap()
    );
}

#[test]
fn an_oversized_request_is_refused_before_any_decision() {
    let controls = admitted_controls("oversized");
    let mut large = query(&controls, DOCKER);
    large.command_text = "x".repeat(EXTENSION_ALLOW_HINT_MAX_BYTES);
    let error = evaluate_extension_allow_hint(&request(large), Some(&controls)).unwrap_err();
    assert_eq!(error, "native_extension_allow_hint_too_large");
}

#[test]
fn the_feature_is_advertised() {
    assert!(
        crate::resident_op_features::RESIDENT_OP_FEATURES.contains(&EXTENSION_ALLOW_HINT_FEATURE)
    );
}

#[test]
fn resident_transport_binds_errors_and_rejects_unknown_fields() {
    let envelope = |schema: &str, extra: Option<(&str, Value)>| {
        let mut query = json!({
            "kind": EXTENSION_ALLOW_HINT_QUERY_KIND,
            "command_text": "git status",
            "canonical_command": {},
            "native_extension_evidence": {},
            "control_snapshot": {},
        });
        if let Some((key, value)) = extra {
            query[key] = value;
        }
        json!({
            "operation": "extension_allow_hint",
            "request": {"schema": schema, "request_id": "req-hint", "query": query},
        })
        .to_string()
    };
    let out =
        crate::resident_protocol::evaluate_resident_bytes(envelope("bogus", None).as_bytes(), None)
            .expect("a foreign schema is a bound reply");
    let reply: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(reply["schema"], EXTENSION_ALLOW_HINT_RESULT_SCHEMA);
    assert_eq!(reply["request_id"], "req-hint");
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_extension_allow_hint_schema_mismatch");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    assert!(crate::resident_protocol::evaluate_resident_bytes(
        envelope(
            EXTENSION_ALLOW_HINT_REQUEST_SCHEMA,
            Some(("surprise", json!(true)))
        )
        .as_bytes(),
        None
    )
    .is_err());
}
