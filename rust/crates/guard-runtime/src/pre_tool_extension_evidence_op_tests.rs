use super::*;
use guard_command::CommandModelRequestV1;
use guard_contracts::{
    ExtensionAllowHintQueryV1, ExtensionAllowHintRequestV1, ExtensionAllowHintResultV1,
    EXTENSION_ALLOW_HINT_QUERY_KIND, EXTENSION_ALLOW_HINT_REQUEST_SCHEMA,
};

const DOCKER_CONTEXT: &str = "docker context use staging";
const DOCKER_RULE: &str = "command.container-runtime.docker-sensitive";
const DOCKER_PERMISSION: &str = "command.container-runtime.permission.docker-sensitive";

fn admitted_controls(name: &str) -> CompiledNativeCommandControls {
    let home = std::env::temp_dir().join(format!(
        "guard-pre-tool-extension-evidence-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    crate::contributed_mcp_catalog_test_support::controls_for(&home, false, &[], &[])
}

fn request(command: &str) -> PreToolRequestV1 {
    PreToolRequestV1 {
        model: CommandModelRequestV1 {
            command: command.into(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "guard-shell".into(),
        },
        cwd: None,
        home_dir: None,
        execution_environment: None,
        extension_evidence: true,
    }
}

#[test]
fn an_extension_review_carries_the_evidence_it_was_decided_on() {
    let controls = admitted_controls("docker");
    let response = evidence_response(&request(DOCKER_CONTEXT), Some(&controls)).unwrap();
    assert_eq!(response["minimum_action"], "review");
    assert_eq!(response["decision"], "deny");
    assert_eq!(response["explicitly_benign"], false);
    assert_eq!(response["command_model"]["normalized_text"], DOCKER_CONTEXT);
    let binding = &response["command_extensions"]["binding"];
    let control = serde_json::to_value(controls.control_binding()).unwrap();
    assert_eq!(
        binding["control_effective_digest"],
        control["effective_digest"]
    );
    assert_eq!(binding["control_revision"], control["revision"]);
    let rules: Vec<&str> = response["command_extensions"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|observation| observation["rule_id"].as_str())
        .collect();
    assert!(rules.contains(&DOCKER_RULE), "{rules:?}");
}

/// The evidence is what the review inbox's allow hint is resolved against.
/// A review without it is never hinted, which left every extension review
/// with no setup guidance.
#[test]
fn the_allow_hint_accepts_the_evidence_and_names_the_permission() {
    let controls = admitted_controls("hint");
    let response = evidence_response(&request(DOCKER_CONTEXT), Some(&controls)).unwrap();
    let hint_request = ExtensionAllowHintRequestV1 {
        schema: EXTENSION_ALLOW_HINT_REQUEST_SCHEMA.into(),
        request_id: "evidence-hint".into(),
        query: ExtensionAllowHintQueryV1 {
            kind: EXTENSION_ALLOW_HINT_QUERY_KIND.into(),
            command_text: DOCKER_CONTEXT.into(),
            canonical_command: response["command_model"].clone(),
            native_extension_evidence: response,
            control_snapshot: serde_json::to_value(controls.control_binding()).unwrap(),
            cwd: None,
            home_dir: None,
            reduction_budget_ms: None,
        },
    };
    let bytes = crate::extension_allow_hint_op::evaluate_extension_allow_hint(
        &hint_request,
        Some(&controls),
    )
    .unwrap();
    let result: ExtensionAllowHintResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok", "{}", result.code);
    let hint = result
        .payload
        .unwrap()
        .hint
        .expect("a docker review is hinted");
    assert_eq!(hint.permission_ids, vec![DOCKER_PERMISSION.to_owned()]);
}

#[test]
fn without_admitted_controls_the_answer_carries_no_evidence() {
    let response = evidence_response(&request(DOCKER_CONTEXT), None).unwrap();
    assert!(response.get("command_extensions").is_none());
    assert_eq!(response["command_model"]["normalized_text"], DOCKER_CONTEXT);
}

#[test]
fn the_plain_review_is_unchanged_and_the_flag_is_routed() {
    let envelope = |flag: Option<bool>| {
        let mut request = serde_json::json!({
            "command": DOCKER_CONTEXT,
            "dialect": "posix",
            "transport": "shell_string",
            "extraction_provenance": "guard-shell",
        });
        if let Some(flag) = flag {
            request["extension_evidence"] = Value::Bool(flag);
        }
        serde_json::json!({"operation": "pre_tool_use", "request": request}).to_string()
    };
    for flag in [None, Some(false), Some(true)] {
        let out =
            crate::resident_protocol::evaluate_resident_bytes(envelope(flag).as_bytes(), None)
                .unwrap();
        let reply: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(reply["command_model"]["normalized_text"], DOCKER_CONTEXT);
        assert!(reply.get("command_extensions").is_none(), "{flag:?}");
    }
}

#[test]
fn the_feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&PRE_TOOL_EXTENSION_EVIDENCE_FEATURE));
}
