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
fn invalid_stamped_path_keeps_the_callers_path() {
    let workspace = std::env::current_dir().expect("workspace");
    let request = HookConnectorFactsRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: "connector-path".to_owned(),
        payload: json!({
            "tool_input": {"command": "lanectl status"},
            "guard_execution_environment": {"path": "bad\u{0}path"}
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
        output["result"]["connector_lookup"]["env"]["PATH"],
        "/system/bin"
    );
}

#[test]
fn oversized_lookup_is_omitted() {
    let workspace = std::env::current_dir().expect("workspace");
    let request = HookConnectorFactsRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: "connector-size".to_owned(),
        payload: json!({"tool_input": {"command": "lanectl status"}}),
        reason_code: "native_command_review_required".to_owned(),
        workspace: Some(workspace.to_string_lossy().into_owned()),
        home_dir: None,
        user_home: "/synthetic/home".to_owned(),
        env: [("BIG".to_owned(), "x".repeat(MAX_LOOKUP_BYTES))]
            .into_iter()
            .collect(),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert!(output["result"]["connector_lookup"].is_null());
}

#[test]
fn whitespace_directory_path_is_resolved_without_trimming() {
    let root = tempfile::tempdir().expect("tempdir");
    let workspace = root.path().join(" spaced ");
    std::fs::create_dir(&workspace).expect("workspace");
    let request = HookConnectorFactsRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: "connector-cwd".to_owned(),
        payload: json!({"cwd": workspace.to_string_lossy(), "tool_input": {"command": "lanectl status"}}),
        reason_code: "native_workspace_containment_executable_outside_roots".to_owned(),
        workspace: None,
        home_dir: None,
        user_home: "/synthetic/home".to_owned(),
        env: BTreeMap::new(),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    let resolved = workspace.canonicalize().expect("resolved workspace");
    assert_eq!(
        output["result"]["connector_lookup"]["cwd"],
        resolved.to_string_lossy().as_ref()
    );
}

#[test]
fn relative_or_missing_directory_has_no_lookup() {
    for payload in [
        json!({"cwd": "relative", "tool_input": {"command": "lanectl status"}}),
        json!({"tool_input": {"command": "lanectl status"}}),
    ] {
        let request = HookConnectorFactsRequestV1 {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: "connector-cwd-invalid".to_owned(),
            payload,
            reason_code: "native_command_review_required".to_owned(),
            workspace: None,
            home_dir: None,
            user_home: "/synthetic/home".to_owned(),
            env: BTreeMap::new(),
        };
        let output: Value =
            serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
        assert!(output["result"]["connector_lookup"].is_null());
    }
}

#[test]
fn non_recognition_is_required_for_a_connector_lookup() {
    let workspace = std::env::current_dir().expect("workspace");
    let request = HookConnectorFactsRequestV1 {
        schema: REQUEST_SCHEMA.to_owned(),
        request_id: "connector-2".to_owned(),
        payload: json!({"tool_input": {"command": "lanectl status"}}),
        reason_code: "native_network_review".to_owned(),
        workspace: Some(workspace.to_string_lossy().into_owned()),
        home_dir: None,
        user_home: "/synthetic/home".to_owned(),
        env: BTreeMap::new(),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert!(output["result"]["connector_lookup"].is_null());
}
