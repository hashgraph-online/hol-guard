use super::*;
use serde_json::json;

#[test]
fn connector_lookup_is_resident_owned_and_preserves_command_whitespace() {
    let workspace = std::env::current_dir().expect("workspace");
    let request = HookConnectorFactsRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: "connector-1".to_owned(),
        payload: json!({
            "tool_input": {"command": "  lanectl status  "},
            "guard_execution_environment": {"path": "/agent/bin"}
        }),
        reason_code: "native_command_review_required".to_owned(),
        workspace: Some(workspace.to_string_lossy().into_owned()),
        home_dir: None,
        user_home: "/synthetic/home".to_owned(),
        env: [("PATH".to_owned(), "/system/bin".to_owned())]
            .into_iter()
            .collect(),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(
        output["result"]["connector_lookup"]["command"],
        "  lanectl status  "
    );
    assert_eq!(
        output["result"]["connector_lookup"]["env"]["PATH"],
        "/agent/bin"
    );
}

#[test]
fn non_recognition_is_required_for_a_connector_lookup() {
    let request = HookConnectorFactsRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: "connector-2".to_owned(),
        payload: json!({"tool_input": {"command": "lanectl status"}}),
        reason_code: "native_network_review".to_owned(),
        workspace: None,
        home_dir: None,
        user_home: "/synthetic/home".to_owned(),
        env: BTreeMap::new(),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert!(output["result"]["connector_lookup"].is_null());
}
