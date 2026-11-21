//! Naming the review a package intent earns.
//!
//! The artifact id the op returns is the key a saved package approval is
//! stored under, so these pin three things: the id is the one the runtime's own
//! builder derives, the exact request values survive the wire, and a request
//! the resident cannot read is refused rather than named from a partial intent.

use guard_command::package_intent_common::{
    build_package_request_artifact, PackageIntent, PackageIntentTarget,
};
use guard_contracts::{PackageRequestArtifactRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::{json, Value};

use super::evaluate_package_request_artifact_request;

fn exact_intent_payload() -> Value {
    json!({
        "package_manager": "npm",
        "intent_kind": "install",
        "command_tokens": ["npm", "install", "left-pad@https://token@example.test/x.tgz"],
        "redacted_command": "npm install left-pad@https://example.test/x.tgz",
        "targets": [{
            "ecosystem": "npm",
            "package_name": "left-pad",
            "raw_spec": "left-pad@https://token@example.test/x.tgz",
            "requested_specifier": "1.3.0",
            "source_url": "https://token@example.test/x.tgz",
            "source_kind": "url",
            "source_repository": null,
            "source_revision_kind": null,
            "source_identity": null,
            "source_invalid_reason": null,
            "alias": null,
            "dependency_group": null,
            "extras": [],
            "editable": false,
        }],
        "manifest_paths": ["/work/package.json"],
        "lockfile_paths": [],
        "flags": [],
        "notes": [],
        "local_executions": [],
        "execution_context_hashes": [],
        "execution_context_cwds": ["/work"],
        "execution_context_reason_codes": [],
        "routine_local_runner": false,
    })
}

fn expected_intent() -> PackageIntent {
    PackageIntent {
        package_manager: "npm".to_owned(),
        intent_kind: "install",
        command_tokens: vec![
            "npm".to_owned(),
            "install".to_owned(),
            "left-pad@https://token@example.test/x.tgz".to_owned(),
        ],
        redacted_command: "npm install left-pad@https://example.test/x.tgz".to_owned(),
        targets: vec![PackageIntentTarget {
            ecosystem: "npm".to_owned(),
            package_name: Some("left-pad".to_owned()),
            raw_spec: "left-pad@https://token@example.test/x.tgz".to_owned(),
            requested_specifier: Some("1.3.0".to_owned()),
            source_url: Some("https://token@example.test/x.tgz".to_owned()),
            source_kind: Some("url".to_owned()),
            ..PackageIntentTarget::default()
        }],
        manifest_paths: vec!["/work/package.json".to_owned()],
        lockfile_paths: Vec::new(),
        flags: Vec::new(),
        notes: Vec::new(),
        local_executions: Vec::new(),
        execution_context_hashes: Vec::new(),
        execution_context_cwds: vec!["/work".to_owned()],
        execution_context_reason_codes: Vec::new(),
        routine_local_runner: false,
    }
}

fn request(intent: Value) -> PackageRequestArtifactRequestV1 {
    PackageRequestArtifactRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        intent,
        harness: "codex".to_owned(),
        config_path: "hol-guard.toml".to_owned(),
        source_scope: "project".to_owned(),
    }
}

fn evaluate(request: &PackageRequestArtifactRequestV1) -> Value {
    let bytes = evaluate_package_request_artifact_request(request).expect("op answers");
    serde_json::from_slice(&bytes).expect("op answers JSON")
}

#[test]
fn the_artifact_is_the_one_the_runtimes_own_builder_derives() {
    let result = evaluate(&request(exact_intent_payload()));
    let expected =
        build_package_request_artifact("codex", &expected_intent(), "hol-guard.toml", "project");

    assert_eq!(result["status"], json!("ok"));
    assert_eq!(result["code"], json!("ok"));
    assert_eq!(result["request_id"], json!("req-1"));
    assert_eq!(result["payload"], expected.to_wire());
    assert_eq!(
        result["payload"]["artifact_id"],
        json!(expected.artifact_id)
    );
}

#[test]
fn the_exact_targets_come_back_as_private_metadata_only() {
    let result = evaluate(&request(exact_intent_payload()));

    // The exact spelling enforcement needs, kept out of the public artifact.
    assert_eq!(
        result["payload"]["runtime_private_metadata"]["package_targets"][0]["raw_spec"],
        json!("left-pad@https://token@example.test/x.tgz")
    );
    assert_ne!(
        result["payload"]["metadata"]["targets"][0]["raw_spec"],
        json!("left-pad@https://token@example.test/x.tgz")
    );
}

#[test]
fn a_redacted_target_would_name_a_different_review() {
    let exact = evaluate(&request(exact_intent_payload()));
    let mut redacted_payload = exact_intent_payload();
    redacted_payload["targets"][0]["raw_spec"] = json!("left-pad@https://example.test/x.tgz");
    let redacted = evaluate(&request(redacted_payload));

    // Why the wire carries `to_execution_dict`: sending the sanitized spelling
    // would re-key every saved approval for this request.
    assert_ne!(
        exact["payload"]["artifact_id"],
        redacted["payload"]["artifact_id"]
    );
}

#[test]
fn an_intent_that_will_not_decode_is_refused() {
    let mut broken = exact_intent_payload();
    broken["intent_kind"] = json!("uninstall");
    let result = evaluate(&request(broken));

    assert_eq!(result["status"], json!("error"));
    assert_eq!(result["code"], json!("invalid_package_intent"));
    assert_eq!(result["payload"], Value::Null);
}

#[test]
fn a_request_on_another_schema_is_refused() {
    let mut mismatched = request(exact_intent_payload());
    mismatched.schema = "guard-package-authority-request.v0".to_owned();
    let result = evaluate(&mismatched);

    assert_eq!(result["status"], json!("error"));
    assert_eq!(result["code"], json!("schema_mismatch"));
}

#[test]
fn every_answer_is_bound_to_the_request_that_asked_it() {
    let ok = evaluate(&request(exact_intent_payload()));
    let mut other = request(exact_intent_payload());
    other.request_id = "req-2".to_owned();
    let second = evaluate(&other);

    assert_ne!(ok["request_sha256"], json!(""));
    assert_ne!(ok["request_sha256"], second["request_sha256"]);
    assert_eq!(second["request_id"], json!("req-2"));
}
