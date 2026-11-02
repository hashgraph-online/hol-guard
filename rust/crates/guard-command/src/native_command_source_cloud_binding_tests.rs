use super::*;
use serde_json::json;

const COMMAND_SOURCE: &[u8] = include_bytes!("../tests/fixtures/command-source-example.v1.json");
const LOCAL_MCP: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contributions/mcp-servers/mcp.filesystem.json"
));
const REMOTE_MCP: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contributions/mcp-servers/mcp.instapods.json"
));
const PERMISSION: &str = "command.example-cli.permission.destroy";

fn bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}

fn command_binding() -> Value {
    json!({
        "schemaVersion": BINDING_CONTRIBUTION_SCHEMA,
        "extensionId": "command.example-cli",
        "bindings": [{
            "actionId": "example.resource.destroy",
            "permissionId": PERMISSION,
            "effect": "destructive",
            "resource": {"kind": "resource", "argument": "name"},
            "requiredCapabilities": [],
            "cloudSupport": "portable-policy"
        }]
    })
}

fn remote_binding() -> Value {
    json!({
        "schemaVersion": BINDING_CONTRIBUTION_SCHEMA,
        "extensionId": "mcp.instapods",
        "bindings": [{
            "actionId": "instapods.pod.delete",
            "tool": "delete_pod",
            "effect": "destructive",
            "requiredCapabilities": ["egress-pinned", "bounded-output", "resource-allowlist"],
            "cloudSupport": "cloud-executable"
        }]
    })
}

#[test]
fn admits_policy_bindings_for_commands_and_executable_bindings_for_remote_servers() {
    let command =
        admit_binding_contribution(&bytes(command_binding()), COMMAND_SOURCE, false).unwrap();
    assert_eq!(command.bindings[0].effect, ActionEffect::Destructive);
    assert_eq!(
        command.bindings[0].cloud_support,
        CloudSupport::PortablePolicy
    );

    let remote = admit_binding_contribution(&bytes(remote_binding()), REMOTE_MCP, true).unwrap();
    assert_eq!(remote.bindings[0].tool.as_deref(), Some("delete_pod"));
    assert!(remote.bindings[0]
        .required_capabilities
        .contains(&TargetCapability::ResourceAllowlist));
}

#[test]
fn legacy_contributions_stay_local_only_and_reject_inline_cloud_fields() {
    let mut command: Value = serde_json::from_slice(COMMAND_SOURCE).unwrap();
    assert!(BindingTarget::from_source(COMMAND_SOURCE, false).is_ok());
    command["extension"]["cloud_bindings"] = json!([]);
    assert_eq!(
        BindingTarget::from_source(&bytes(command), false).unwrap_err(),
        "command_source_contract_invalid"
    );

    let mut server: Value = serde_json::from_slice(REMOTE_MCP).unwrap();
    assert!(BindingTarget::from_source(REMOTE_MCP, true).is_ok());
    server["cloudBindings"] = json!([]);
    assert_eq!(
        BindingTarget::from_source(&bytes(server), true).unwrap_err(),
        "command_source_mcp_contract_invalid"
    );
}

#[test]
fn rejects_unknown_fields_defaults_and_code_at_every_level() {
    let cases = [
        ("/allowDefault", json!(true)),
        ("/include", json!("https://example.com/more.json")),
        ("/bindings/0/defaultDecision", json!("allow")),
        ("/bindings/0/script", json!("return true")),
        ("/bindings/0/resource/extractor", json!("$.channel")),
    ];
    for (pointer, extra) in cases {
        let mut value = command_binding();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        let target = if parent.is_empty() {
            &mut value
        } else {
            value.pointer_mut(parent).unwrap()
        };
        target[key] = extra;
        assert_eq!(
            parse_binding_contribution(&bytes(value)).unwrap_err(),
            "cloud_binding_contract_invalid",
            "{pointer}"
        );
    }
    let mut unknown_effect = command_binding();
    unknown_effect["bindings"][0]["effect"] = json!("harmless");
    let mut unknown_capability = command_binding();
    unknown_capability["bindings"][0]["requiredCapabilities"] = json!(["trust-me"]);
    let mut unknown_support = command_binding();
    unknown_support["bindings"][0]["cloudSupport"] = json!("local-only");
    for value in [unknown_effect, unknown_capability, unknown_support] {
        assert_eq!(
            parse_binding_contribution(&bytes(value)).unwrap_err(),
            "cloud_binding_contract_invalid"
        );
    }
}

#[test]
fn rejects_malformed_json_and_other_schema_versions() {
    assert_eq!(
        parse_binding_contribution(br#"{"schemaVersion":"a","schemaVersion":"b"}"#).unwrap_err(),
        "cloud_binding_json_invalid"
    );
    let mut future = command_binding();
    future["schemaVersion"] = json!("guard.cloud-action-binding-contribution.v2");
    assert_eq!(
        parse_binding_contribution(&bytes(future)).unwrap_err(),
        "cloud_binding_unsupported_version"
    );
    let mut missing = command_binding();
    missing.as_object_mut().unwrap().remove("schemaVersion");
    assert_eq!(
        parse_binding_contribution(&bytes(missing)).unwrap_err(),
        "cloud_binding_contract_invalid"
    );
}

#[test]
fn rejects_unsafe_binding_shapes() {
    let mut empty = command_binding();
    empty["bindings"] = json!([]);
    let mut bad_action = command_binding();
    bad_action["bindings"][0]["actionId"] = json!("Example.Destroy");
    let mut duplicate = command_binding();
    let first = duplicate["bindings"][0].clone();
    duplicate["bindings"].as_array_mut().unwrap().push(first);
    let mut bad_resource = command_binding();
    bad_resource["bindings"][0]["resource"]["argument"] = json!("two words");
    let mut no_floor = remote_binding();
    no_floor["bindings"][0]["requiredCapabilities"] = json!(["egress-pinned"]);
    for (value, code) in [
        (empty, "cloud_binding_contract_invalid"),
        (bad_action, "cloud_binding_action_invalid"),
        (duplicate, "cloud_binding_duplicate_action"),
        (bad_resource, "cloud_binding_resource_invalid"),
        (no_floor, "cloud_binding_missing_required_capability"),
    ] {
        assert_eq!(parse_binding_contribution(&bytes(value)).unwrap_err(), code);
    }
}

#[test]
fn references_must_name_what_the_extension_already_declares() {
    let mut wrong_extension = command_binding();
    wrong_extension["extensionId"] = json!("command.other");
    let mut unknown_permission = command_binding();
    unknown_permission["bindings"][0]["permissionId"] =
        json!("command.example-cli.permission.other");
    let mut tool_on_command = command_binding();
    tool_on_command["bindings"][0]["tool"] = json!("destroy");
    let mut neither = command_binding();
    neither["bindings"][0]
        .as_object_mut()
        .unwrap()
        .remove("permissionId");
    for (value, code) in [
        (wrong_extension, "cloud_binding_extension_mismatch"),
        (unknown_permission, "cloud_binding_permission_unknown"),
        (tool_on_command, "cloud_binding_reference_invalid"),
        (neither, "cloud_binding_reference_invalid"),
    ] {
        assert_eq!(
            admit_binding_contribution(&bytes(value), COMMAND_SOURCE, false).unwrap_err(),
            code
        );
    }

    let mut unknown_tool = remote_binding();
    unknown_tool["bindings"][0]["tool"] = json!("drop_everything");
    let mut catch_all = remote_binding();
    catch_all["bindings"][0]["tool"] = json!("other");
    for value in [unknown_tool, catch_all] {
        assert_eq!(
            admit_binding_contribution(&bytes(value), REMOTE_MCP, true).unwrap_err(),
            "cloud_binding_tool_unknown"
        );
    }
}

#[test]
fn hosted_execution_never_targets_a_command_line_or_local_server() {
    let mut command = command_binding();
    command["bindings"][0]["cloudSupport"] = json!("cloud-executable");
    command["bindings"][0]["requiredCapabilities"] = json!(["egress-pinned", "bounded-output"]);
    assert_eq!(
        admit_binding_contribution(&bytes(command), COMMAND_SOURCE, false).unwrap_err(),
        "cloud_binding_local_only_target"
    );

    let mut local = remote_binding();
    local["extensionId"] = json!("mcp.filesystem");
    local["bindings"][0]["tool"] = json!("write_file");
    assert_eq!(
        admit_binding_contribution(&bytes(local.clone()), LOCAL_MCP, true).unwrap_err(),
        "cloud_binding_local_only_target"
    );
    local["bindings"][0]["cloudSupport"] = json!("portable-policy");
    assert!(admit_binding_contribution(&bytes(local), LOCAL_MCP, true).is_ok());
}
