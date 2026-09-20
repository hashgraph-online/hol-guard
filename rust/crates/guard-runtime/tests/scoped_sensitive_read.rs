#[path = "../src/policy_scoped_sensitive_read.rs"]
mod sensitive_read;

use guard_contracts::GuardHookEnvelopeV2;
use sensitive_read::derive_sensitive_read_artifact;
use serde_json::{json, Value};

fn envelope(case: &Value) -> GuardHookEnvelopeV2 {
    serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "harness":case["harness"], "event":"PreToolUse",
        "raw_payload":case["payload"], "source":case["source"],
        "policy_generation":1, "policy_snapshot":{}
    }))
    .unwrap()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/sensitive-read-sources.json")).unwrap()
}

#[test]
fn sensitive_read_identities_match_actual_python_hook_producer() {
    let fixture = fixture();
    assert_eq!(
        fixture["contentBinding"],
        "request path and tool identity only; no secret file bytes"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 32);
    for case in cases {
        let request = envelope(case);
        let identity =
            derive_sensitive_read_artifact(&request, case["harness"].as_str().unwrap()).unwrap();
        assert_eq!(identity.artifact_id, case["artifactId"], "{}", case["name"]);
        assert_eq!(
            identity.normalized_path, case["normalizedPath"],
            "{}",
            case["name"]
        );
        assert_eq!(identity.path_class, case["pathClass"], "{}", case["name"]);
        assert_eq!(identity.risk_class, "local_secret_read");
    }
}

#[test]
fn caller_labels_and_content_hashes_cannot_replace_requested_path_identity() {
    let mut request = envelope(&fixture()["cases"][0]);
    let original = derive_sensitive_read_artifact(&request, "codex").unwrap();
    request.raw_payload["artifactId"] = json!("synthetic:forged");
    request.raw_payload["artifactHash"] = json!("a".repeat(64));
    assert_eq!(
        derive_sensitive_read_artifact(&request, "codex").unwrap(),
        original
    );
    request.raw_payload["tool_input"]["file_path"] = json!("nested/.npmrc");
    let changed = derive_sensitive_read_artifact(&request, "codex").unwrap();
    assert_ne!(changed.artifact_id, original.artifact_id);
    assert_eq!(changed.path_class, original.path_class);
    request.raw_payload["tool_input"]["file_path"] = json!("./nested/../.npmrc");
    assert_eq!(
        derive_sensitive_read_artifact(&request, "codex").unwrap(),
        original
    );
}

#[test]
fn ambiguous_ingress_and_competing_scope_or_event_fields_are_refused() {
    let original = envelope(&fixture()["cases"][0]);
    for (key, value) in [
        ("toolName", json!("Read")),
        ("arguments", json!({"file_path":".npmrc"})),
        ("source_scope", json!("user")),
        ("sourceScope", json!(null)),
        ("eventName", json!("PreToolUse")),
        ("event", json!("PostToolUse")),
        ("guard_source_ref", json!({})),
        ("guard_payload_ref", json!({})),
        ("cwd", json!("/synthetic/different-workspace")),
        ("policy_action", json!("block")),
        ("prompt", json!("synthetic unmodeled prompt")),
        ("toolCalls", json!([])),
        ("mcp_server", json!("synthetic")),
    ] {
        let mut request = original.clone();
        request.raw_payload[key] = value;
        assert!(
            derive_sensitive_read_artifact(&request, "codex").is_err(),
            "{key}"
        );
    }
    let mut request = original.clone();
    request.raw_payload["source_scope"] = json!("project");
    request.raw_payload["sourceScope"] = json!("project");
    assert!(derive_sensitive_read_artifact(&request, "codex").is_err());
    assert!(derive_sensitive_read_artifact(&original, "claude-code").is_err());
    request = original;
    request.event = "PostToolUse".to_owned();
    assert!(derive_sensitive_read_artifact(&request, "codex").is_err());
}

#[test]
fn unproven_tools_argument_shapes_and_path_interpretations_are_refused() {
    let original = envelope(&fixture()["cases"][0]);
    for tool in [
        "mcp__synthetic__Read",
        "Unknown",
        "Write",
        "Bash",
        " Read",
        "read ",
    ] {
        let mut request = original.clone();
        request.raw_payload["tool_name"] = json!(tool);
        assert!(
            derive_sensitive_read_artifact(&request, "codex").is_err(),
            "{tool}"
        );
    }
    let mut cline = original.clone();
    cline.harness = "cline".to_owned();
    cline.raw_payload["tool_name"] = json!("View");
    assert!(derive_sensitive_read_artifact(&cline, "cline").is_err());
    for arguments in [
        json!({}),
        json!({"file_path":null}),
        json!({"file_path":[".npmrc"]}),
        json!({"file_path":".npmrc","path":".env"}),
        json!({"nested":{"file_path":".npmrc"}}),
        json!({"file_path":".npmrc","offset":1}),
        json!("{\"file_path\":\".npmrc\"}"),
    ] {
        let mut request = original.clone();
        request.raw_payload["tool_input"] = arguments;
        assert!(derive_sensitive_read_artifact(&request, "codex").is_err());
    }
    for path in [
        "",
        "README.md",
        ".npmrc ",
        "'.npmrc'",
        "~other/.npmrc",
        "~//.npmrc",
        "~///.npmrc",
        "$HOME/.npmrc",
        "//synthetic/.npmrc",
        "C:\\synthetic\\.npmrc",
        "../café/.npmrc",
        "*/.npmrc",
        "./.gnupg/.aws/credentials",
        "./.aws/credentials/other",
        "./.ssh/id_ed25519/other",
        ".terraform.tfvars",
        "./.../credentials",
    ] {
        let mut request = original.clone();
        request.raw_payload["tool_input"]["file_path"] = json!(path);
        assert!(
            derive_sensitive_read_artifact(&request, "codex").is_err(),
            "{path}"
        );
    }
    let mut request = original;
    request.source.cwd = Some("relative".to_owned());
    assert!(derive_sensitive_read_artifact(&request, "codex").is_err());
}
