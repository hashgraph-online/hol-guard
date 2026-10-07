use std::sync::Arc;

use guard_contracts::NativeCommandControlBindingV1;
use serde_json::{json, Value};

use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::{source::compile_addition_with_mcp, NativeCommandProgram};
use crate::native_mcp_package_pin::{configured_package_pin, valid_package_pin};

const FILESYSTEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contributions/mcp-servers/mcp.filesystem.json"
));
const TRUST: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contracts/extensions/trust-class-map.v1.json"
));

fn source() -> Value {
    let mut value: Value = serde_json::from_slice(FILESYSTEM).unwrap();
    value["id"] = json!("mcp.pinned-fixture");
    value["launch"] = json!({
        "kind": "package-launcher", "command": "npx",
        "package": "fixture-mcp", "packageVersion": "0.1.18"
    });
    value
}

fn controls() -> CompiledNativeCommandControls {
    controls_for_state("block")
}

fn controls_for_state(state: &str) -> CompiledNativeCommandControls {
    let mut source = source();
    for tool in source["tools"].as_array_mut().unwrap() {
        if tool["name"] == "write_file" {
            tool["state"] = json!(state);
        }
    }
    let output =
        compile_addition_with_mcp(&[], &[&serde_json::to_vec(&source).unwrap()], TRUST).unwrap();
    assert_eq!(
        output.catalog[0]["permissions"][0]["example_command"],
        "npx -y fixture-mcp@0.1.18"
    );
    let program = Arc::new(
        NativeCommandProgram::from_packaged_bytes(&serde_json::to_vec(&output.program).unwrap())
            .unwrap(),
    );
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected", "revision": 1,
        "managed_revision": 0, "effective_digest": "", "layers": [{
            "schema_version": "1.0.0", "kind": "local-admin",
            "catalog_digest": program.catalog_digest, "global_lockdown": false,
            "controls": [{"target_kind": "extension", "target_id": "command.mcp-pinned-fixture",
                          "state": "enabled"}]
        }]
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::for_program(&binding, program).unwrap()
}

fn observed(controls: &CompiledNativeCommandControls, payload: &Value) -> bool {
    let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        payload,
        Some(controls),
        None,
    );
    result.command_extensions.is_some_and(|batch| {
        batch
            .permission_observations
            .iter()
            .any(|row| row.extension_id == "command.mcp-pinned-fixture")
    })
}

#[test]
fn native_package_pin_rejects_tags_ranges_and_other_ecosystems() {
    for (command, package, version) in [
        ("npx", "fixture-mcp", "latest"),
        ("npx", "fixture-mcp", "^0.1.18"),
        ("npx", "fixture-mcp", "00.1.18"),
        ("npx", "fixture-mcp", "0.1.18\n"),
        ("pipx", "fixture-mcp", "0.1.18"),
        ("uvx", "fixture-mcp", "0.1.18"),
        ("npx", "fixture-mcp@0.1.18", "0.1.18"),
    ] {
        assert!(!valid_package_pin(command, package, version));
        let mut value = source();
        value["launch"]["command"] = json!(command);
        value["launch"]["package"] = json!(package);
        value["launch"]["packageVersion"] = json!(version);
        assert!(
            compile_addition_with_mcp(&[], &[&serde_json::to_vec(&value).unwrap()], TRUST,)
                .is_err()
        );
    }
    assert!(valid_package_pin("npx", "@example/fixture", "0.1.18"));
    let mut value = source();
    value["launch"]["packageVersion"] = Value::Null;
    assert!(
        compile_addition_with_mcp(&[], &[&serde_json::to_vec(&value).unwrap()], TRUST,).is_err()
    );
}

#[test]
fn native_package_pin_enforces_npm_name_length() {
    for package in ["a".repeat(214), format!("@scope/{}", "a".repeat(207))] {
        assert!(valid_package_pin("npx", &package, "0.1.18"));
    }
    for package in ["a".repeat(215), format!("@scope/{}", "a".repeat(208))] {
        assert!(!valid_package_pin("npx", &package, "0.1.18"));
        let mut value = source();
        value["launch"]["package"] = json!(package);
        assert!(
            compile_addition_with_mcp(&[], &[&serde_json::to_vec(&value).unwrap()], TRUST).is_err()
        );
    }
}

#[test]
fn native_package_pin_rejects_environment_redirection() {
    let mut identity = json!({
        "command": "npx", "package_name": "fixture-mcp", "package_version": "0.1.18",
        "package_source": "default", "transport": "stdio", "env_keys": ["REDIS_URL"]
    });
    assert!(configured_package_pin(&identity).is_some());
    for key in [
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_CONFIG_DIRS",
        "BUN_INSTALL",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PATH",
        "NPM_CONFIG_CACHE",
        "YARN_CACHE_FOLDER",
        "BUN_INSTALL_CACHE_DIR",
    ] {
        identity["env_keys"] = json!([key]);
        assert!(configured_package_pin(&identity).is_none(), "{key}");
    }
}

#[test]
fn native_pinned_defaults_require_the_same_complete_server_identity() {
    let identity = json!({
            "command": "npx", "package_name": "fixture-mcp", "package_version": "0.1.18",
            "package_source": "default", "transport": "stdio", "env_keys": []
    });
    assert_eq!(
        configured_package_pin(&identity).as_deref(),
        Some("npx:fixture-mcp@0.1.18")
    );
    for (field, value) in [
        ("package_version", json!("latest")),
        ("package_version", Value::Null),
        ("package_source", json!("registry=unreviewed")),
        ("transport", json!("http")),
        ("package_name", json!("FIXTURE-MCP")),
        ("package_name", json!(" fixture-mcp")),
        ("env_keys", Value::Null),
        ("env_keys", json!([false])),
    ] {
        let mut candidate = identity.clone();
        candidate[field] = value;
        assert!(configured_package_pin(&candidate).is_none(), "{field}");
    }
    for key in [
        "NPM_CONFIG_REGISTRY",
        "npm_config_registry",
        "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_PREFIX",
        "npm_config_@example:registry",
        "YARN_REGISTRY",
        "YARN_NPM_REGISTRY_SERVER",
        "YARN_RC_FILENAME",
        "BUN_CONFIG_REGISTRY",
        "BUN_INSTALL_REGISTRY",
    ] {
        let mut candidate = identity.clone();
        candidate["env_keys"] = json!([key]);
        assert!(configured_package_pin(&candidate).is_none(), "{key}");
    }
    let mut candidate = identity;
    candidate["env_keys"] = json!(["REDIS_URL"]);
    assert!(configured_package_pin(&candidate).is_some());
}

#[test]
fn native_pinned_tightening_floors_survive_missing_or_mismatched_identity() {
    for state in ["block", "review"] {
        let controls = controls_for_state(state);
        let mut payload = json!({
            "tool_name": "mcp__pinned-fixture__write_file", "tool_input": {}
        });
        for identity in [
            Value::Null,
            json!({
                "command": "npx", "package_name": "fixture-mcp", "package_version": "0.1.17",
                "package_source": "default", "transport": "stdio", "env_keys": []
            }),
        ] {
            payload["mcp_server_identity"] = identity;
            assert!(observed(&controls, &payload));
            let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
                "claude-code",
                "PreToolUse",
                &payload,
                Some(&controls),
                None,
            );
            assert_eq!(result.minimum_action, state);
        }
    }
}

#[test]
fn native_pinned_nontightening_defaults_require_exact_configured_identity() {
    let controls = controls_for_state("allow");
    let mut payload = json!({
        "tool_name": "mcp__pinned-fixture__write_file", "tool_input": {},
        "mcp_server_identity": {
        "command": "npx", "package_name": "fixture-mcp", "package_version": "0.1.18",
        "package_source": "default", "transport": "stdio", "env_keys": []
    }});
    assert!(observed(&controls, &payload));
    let mut conflicting = payload.clone();
    conflicting["metadata"] = json!({"mcp_server_identity": {
        "command": "npx", "package_name": "fixture-mcp", "package_version": "0.1.17",
        "package_source": "default", "transport": "stdio", "env_keys": []
    }});
    assert!(!observed(&controls, &conflicting));
    payload["mcp_server_identity"]["package_version"] = json!("0.1.17");
    assert!(!observed(&controls, &payload));
    payload
        .as_object_mut()
        .unwrap()
        .remove("mcp_server_identity");
    for arguments in [
        json!({"package_name": "fixture-mcp", "package_version": "0.1.18"}),
        json!({"package": "npx:fixture-mcp@0.1.18"}),
        json!({"mcp_server_identity": {
            "command": "npx", "package_name": "fixture-mcp", "package_version": "0.1.18",
            "package_source": "default", "transport": "stdio", "env_keys": []
        }}),
    ] {
        payload["tool_input"] = arguments;
        assert!(!observed(&controls, &payload));
    }
    assert!(!observed(&controls, &payload));
}

#[test]
fn native_pinned_floor_stays_inert_without_local_admin_enable() {
    let controls = controls();
    let payload = json!({"tool_name": "mcp__pinned-fixture__write_file", "tool_input": {}});
    assert!(observed(&controls, &payload));
    let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &payload,
        None,
        None,
    );
    assert!(!result.command_extensions.is_some_and(|batch| {
        batch
            .permission_observations
            .iter()
            .any(|row| row.extension_id == "command.mcp-pinned-fixture")
    }));
}
