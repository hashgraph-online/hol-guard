use super::super::cloud_binding::{
    compile_artifact, parse_binding_contribution, BindingTarget, BINDING_CONTRIBUTION_SCHEMA,
};
use super::*;
use serde_json::json;

const COMMAND_SOURCE: &[u8] = include_bytes!("../tests/fixtures/command-source-example.v1.json");
const REMOTE_MCP: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contributions/mcp-servers/mcp.instapods.json"
));
const PROGRAM: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn artifact() -> Value {
    let pairs = [
        (
            json!({
                "schemaVersion": BINDING_CONTRIBUTION_SCHEMA,
                "extensionId": "command.example-cli",
                "bindings": [{
                    "actionId": "example.resource.destroy",
                    "permissionId": "command.example-cli.permission.destroy",
                    "effect": "destructive",
                    "resource": {"kind": "resource", "argument": "name"},
                    "requiredCapabilities": [],
                    "cloudSupport": "portable-policy"
                }]
            }),
            COMMAND_SOURCE,
            false,
        ),
        (
            json!({
                "schemaVersion": BINDING_CONTRIBUTION_SCHEMA,
                "extensionId": "mcp.instapods",
                "bindings": [{
                    "actionId": "instapods.pod.delete",
                    "tool": "delete_pod",
                    "effect": "destructive",
                    "requiredCapabilities": ["egress-pinned", "bounded-output"],
                    "cloudSupport": "cloud-executable"
                }]
            }),
            REMOTE_MCP,
            true,
        ),
    ];
    let parsed: Vec<_> = pairs
        .iter()
        .map(|(binding, source, server)| {
            (
                parse_binding_contribution(&serde_json::to_vec(binding).unwrap()).unwrap(),
                BindingTarget::from_source(source, *server).unwrap(),
            )
        })
        .collect();
    let resolved: Vec<_> = parsed
        .iter()
        .map(|(contribution, target)| (contribution, target.clone()))
        .collect();
    compile_artifact(&resolved, PROGRAM).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

/// Re-sign an edited artifact the way the compiler would, so a test reaches
/// the check behind the digest rather than stopping at the digest itself.
fn resign(mut value: Value) -> Value {
    for action in value["actions"].as_array_mut().into_iter().flatten() {
        action.as_object_mut().unwrap().remove("binding_digest");
        let digest = catalog::digest(BINDING_MEANING_DOMAIN, action).unwrap();
        action["binding_digest"] = json!(digest);
    }
    value.as_object_mut().unwrap().remove("artifact_digest");
    let digest = catalog::digest(BINDING_ARTIFACT_DOMAIN, &value).unwrap();
    value["artifact_digest"] = json!(digest);
    value
}

#[test]
fn reads_compiler_output_and_reports_its_identity() {
    let compiled = artifact();
    let read = read_binding_artifact(&bytes(&compiled)).unwrap();
    assert_eq!(
        read.metadata,
        BindingArtifactMetadata {
            schema: BINDING_ARTIFACT_SCHEMA.to_owned(),
            compiler_version: 1,
            program_digest: PROGRAM.to_owned(),
            artifact_digest: compiled["artifact_digest"].as_str().unwrap().to_owned(),
            action_count: 2,
        }
    );
    let remote = read.get("instapods.pod.delete").unwrap();
    assert_eq!(remote.cloud_support, CloudSupport::CloudExecutable);
    assert_eq!(
        remote.target,
        ArtifactTarget::McpTool {
            tool: "delete_pod".to_owned(),
            endpoint: Some("https://app.instapods.com/api/mcp".to_owned()),
        }
    );
    assert_eq!(
        read.get("example.resource.destroy").unwrap().resource,
        Some(ArtifactResource {
            kind: "resource".to_owned(),
            argument: "name".to_owned(),
        })
    );
    assert_eq!(
        read.actions()
            .map(|action| action.action_id.as_str())
            .collect::<Vec<_>>(),
        ["example.resource.destroy", "instapods.pod.delete"]
    );
    // Formatting is not meaning: pretty-printed output reads the same.
    let pretty = serde_json::to_vec_pretty(&compiled).unwrap();
    assert_eq!(
        read_binding_artifact(&pretty).unwrap().metadata,
        read.metadata
    );
}

#[test]
fn publishes_what_this_build_can_read() {
    let compatibility = binding_artifact_compatibility();
    assert_eq!(compatibility.schema, BINDING_ARTIFACT_SCHEMA);
    assert_eq!(compatibility.compiler_versions, [1]);
    assert_eq!(compatibility.max_actions, MAX_BINDINGS);
    assert_eq!(
        serde_json::to_value(&compatibility).unwrap(),
        json!({
            "schema": "guard.cloud-action-binding-artifact.v1",
            "compiler_versions": [1],
            "max_actions": MAX_BINDINGS,
        })
    );
}

#[test]
fn older_and_newer_formats_fail_as_unsupported_versions() {
    for schema in [
        "guard.cloud-action-binding-artifact.v0",
        "guard.cloud-action-binding-artifact.v2",
        "guard.cloud-action-binding-set.v1",
    ] {
        let mut value = artifact();
        value["schema"] = json!(schema);
        assert_eq!(
            read_binding_artifact(&bytes(&resign(value))).unwrap_err(),
            "cloud_binding_artifact_unsupported_version",
            "{schema}"
        );
    }
    for version in [0, 2, 99] {
        let mut value = artifact();
        value["compiler_version"] = json!(version);
        assert_eq!(
            read_binding_artifact(&bytes(&resign(value))).unwrap_err(),
            "cloud_binding_artifact_unsupported_version",
            "{version}"
        );
    }
    // A newer compiler may add fields; the version gate answers before the
    // shape check, so the caller learns why it cannot read the file.
    let mut future = artifact();
    future["compiler_version"] = json!(2);
    future["revocations"] = json!([]);
    future["actions"][0]["sandbox"] = json!("required");
    assert_eq!(
        read_binding_artifact(&bytes(&future)).unwrap_err(),
        "cloud_binding_artifact_unsupported_version"
    );
}

#[test]
fn unknown_or_missing_fields_are_never_dropped() {
    let mut top = artifact();
    top["defaults"] = json!({"effect": "read"});
    let mut nested = artifact();
    nested["actions"][1]["sandbox"] = json!("none");
    let mut target = artifact();
    target["actions"][1]["target"]["fallback"] = json!(true);
    let mut missing = artifact();
    missing["actions"][0]
        .as_object_mut()
        .unwrap()
        .remove("resource");
    let mut typed = artifact();
    typed["compiler_version"] = json!("1");
    let mut kind = artifact();
    kind["actions"][0]["target"]["kind"] = json!("shell-command");
    for value in [top, nested, target, missing, kind] {
        assert_eq!(
            read_binding_artifact(&bytes(&resign(value))).unwrap_err(),
            "cloud_binding_artifact_malformed"
        );
    }
    assert_eq!(
        read_binding_artifact(&bytes(&typed)).unwrap_err(),
        "cloud_binding_artifact_malformed"
    );
    for raw in [
        &b""[..],
        b"[]",
        b"{\"schema\":\"guard.cloud-action-binding-artifact.v1\",\"schema\":\"x\"}",
    ] {
        assert_eq!(
            read_binding_artifact(raw).unwrap_err(),
            "cloud_binding_artifact_malformed"
        );
    }
}

#[test]
fn edited_artifacts_fail_their_digests() {
    let mut weakened = artifact();
    weakened["actions"][1]["effect"] = json!("read");
    assert_eq!(
        read_binding_artifact(&bytes(&weakened)).unwrap_err(),
        "cloud_binding_artifact_digest_mismatch"
    );
    // Recomputing the action digest alone still breaks the artifact digest.
    let mut action_only = artifact();
    action_only["actions"][1]["effect"] = json!("read");
    let mut meaning = action_only["actions"][1].clone();
    meaning.as_object_mut().unwrap().remove("binding_digest");
    action_only["actions"][1]["binding_digest"] =
        json!(catalog::digest(BINDING_MEANING_DOMAIN, &meaning).unwrap());
    assert_eq!(
        read_binding_artifact(&bytes(&action_only)).unwrap_err(),
        "cloud_binding_artifact_digest_mismatch"
    );
    let mut rebased = artifact();
    rebased["program_digest"] = json!("2".repeat(64));
    assert_eq!(
        read_binding_artifact(&bytes(&rebased)).unwrap_err(),
        "cloud_binding_artifact_digest_mismatch"
    );
    let mut dropped = artifact();
    dropped["actions"].as_array_mut().unwrap().pop();
    assert_eq!(
        read_binding_artifact(&bytes(&dropped)).unwrap_err(),
        "cloud_binding_artifact_digest_mismatch"
    );
}

#[test]
fn rechecks_the_rules_the_compiler_enforced() {
    let mut weak_floor = artifact();
    weak_floor["actions"][1]["required_capabilities"] = json!(["egress-pinned"]);
    assert_eq!(
        read_binding_artifact(&bytes(&resign(weak_floor))).unwrap_err(),
        "cloud_binding_artifact_missing_required_capability"
    );
    let mut command_executes = artifact();
    command_executes["actions"][0]["cloud_support"] = json!("cloud-executable");
    command_executes["actions"][0]["required_capabilities"] =
        json!(["egress-pinned", "bounded-output"]);
    let mut local_server_executes = artifact();
    local_server_executes["actions"][1]["target"]["endpoint"] = Value::Null;
    let mut plain_http = artifact();
    plain_http["actions"][1]["target"]["endpoint"] = json!("http://app.instapods.com/api/mcp");
    let mut bad_id = artifact();
    bad_id["actions"][0]["action_id"] = json!("Example");
    let mut empty = artifact();
    empty["actions"] = json!([]);
    let mut endpoints = Vec::new();
    for endpoint in [
        "https://",
        "https://127.0.0.1/mcp",
        "https://user:secret@app.instapods.com/api/mcp",
        "https://APP.instapods.com/api/mcp",
    ] {
        let mut value = artifact();
        value["actions"][1]["target"]["endpoint"] = json!(endpoint);
        endpoints.push(value);
    }
    for value in [
        command_executes,
        local_server_executes,
        plain_http,
        bad_id,
        empty,
    ]
    .into_iter()
    .chain(endpoints)
    {
        assert_eq!(
            read_binding_artifact(&bytes(&resign(value))).unwrap_err(),
            "cloud_binding_artifact_malformed"
        );
    }

    let mut reversed = artifact();
    reversed["actions"].as_array_mut().unwrap().reverse();
    assert_eq!(
        read_binding_artifact(&bytes(&resign(reversed))).unwrap_err(),
        "cloud_binding_artifact_order_invalid"
    );
    let mut duplicated = artifact();
    let first = duplicated["actions"][0].clone();
    duplicated["actions"][1] = first;
    assert_eq!(
        read_binding_artifact(&bytes(&resign(duplicated))).unwrap_err(),
        "cloud_binding_artifact_order_invalid"
    );
}

#[test]
fn refuses_more_actions_for_one_extension_than_a_contribution_declares() {
    let with = |count: usize| {
        let mut value = artifact();
        let template = value["actions"][1].clone();
        let actions: Vec<Value> = (0..count)
            .map(|index| {
                let mut action = template.clone();
                action["action_id"] = json!(format!("instapods.pod.delete{index:03}"));
                action
            })
            .collect();
        value["actions"] = Value::Array(actions);
        resign(value)
    };
    assert_eq!(
        read_binding_artifact(&bytes(&with(MAX_BINDINGS_PER_EXTENSION)))
            .unwrap()
            .metadata
            .action_count,
        MAX_BINDINGS_PER_EXTENSION
    );
    assert_eq!(
        read_binding_artifact(&bytes(&with(MAX_BINDINGS_PER_EXTENSION + 1))).unwrap_err(),
        "cloud_binding_artifact_limit"
    );
}

#[test]
fn refuses_oversize_artifacts() {
    let mut crowded = artifact();
    let action = crowded["actions"][0].clone();
    crowded["actions"] = Value::Array(vec![action; MAX_BINDINGS + 1]);
    // The bounded decoder stops at MAX_BINDINGS items, before any digest work.
    assert_eq!(
        read_binding_artifact(&bytes(&resign(crowded))).unwrap_err(),
        "cloud_binding_artifact_malformed"
    );
    assert_eq!(
        read_binding_artifact(&vec![b' '; MAX_ARTIFACT_BYTES + 1]).unwrap_err(),
        "cloud_binding_artifact_limit"
    );
}

#[test]
fn an_artifact_answers_only_for_the_program_it_was_compiled_with() {
    let read = read_binding_artifact(&bytes(&artifact())).unwrap();
    assert!(read.require_program(PROGRAM).is_ok());
    assert_eq!(
        read.require_program(&"2".repeat(64)).unwrap_err(),
        "cloud_binding_artifact_program_mismatch"
    );
}
