//! Parity tests for `native_command_extension_evidence` against real
//! `native-command-observations.v1` payloads captured from the packaged
//! native evaluator, and the Python `observations_from_native_evidence`
//! oracle. Each fixture JSON carries `{payload, snapshot, command}`; the
//! `payload` is the full `native_extension_evidence` envelope the resident
//! `evaluate_command` receives.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::canonical_command::CanonicalCommand;
use crate::native_command_catalog::packaged_command_catalog;
use crate::native_command_extension_evidence::{
    observations_from_native_evidence, validate_native_command_observations,
};
use guard_contracts::NativeCommandControlBindingV1;

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    let mut fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("json");
    // Binding digests rotate with the compiled program/catalog pair; substitute
    // the live values so the fixture still exercises the binding check (each
    // mismatched-field test overwrites its own leg afterward).
    if let Ok(catalog) = crate::native_command_catalog::packaged_command_catalog() {
        if let Some(binding) = fixture["payload"]["command_extensions"]["binding"].as_object_mut() {
            binding.insert(
                "program_digest".into(),
                Value::String(catalog.program_digest.clone()),
            );
            binding.insert(
                "catalog_digest".into(),
                Value::String(catalog.catalog_digest.clone()),
            );
        }
    }
    fixture
}

fn command_for(fixture: &Value) -> CanonicalCommand {
    CanonicalCommand {
        normalized_text: fixture["payload"]["command_model"]["normalized_text"]
            .as_str()
            .unwrap()
            .to_owned(),
        dialect: String::new(),
        transport: String::new(),
        extraction_provenance: String::new(),
        wrapper_chain: Vec::new(),
        segments: Vec::new(),
        security_identity: String::new(),
        confidence: String::new(),
        uncertainty_reason: None,
        path_overridden: false,
    }
}

fn snapshot_for(fixture: &Value) -> NativeCommandControlBindingV1 {
    let s = &fixture["snapshot"];
    NativeCommandControlBindingV1 {
        active_security_digest: None,
        schema: "guard.native-command-control-binding.v1".to_owned(),
        program_digest: String::new(),
        catalog_digest: String::new(),
        trust_digest: String::new(),
        health: "protected".to_owned(),
        revision: s["revision"].as_u64().unwrap(),
        managed_revision: s["managed_revision"].as_u64().unwrap(),
        effective_digest: s["effective_digest"].as_str().unwrap().to_owned(),
        layers: Vec::new(),
        authority: None,
    }
}

/// Observation summary for oracle comparison: (extension_id, rule_id,
/// severity, default_mode, uncertainty_reasons, safe_variant_ids,
/// matcher_evidence_len).
#[allow(clippy::type_complexity)]
fn summarize(
    fixture_name: &str,
) -> Vec<(
    String,
    String,
    String,
    String,
    Vec<String>,
    Vec<String>,
    usize,
)> {
    let fixture = fixture(fixture_name);
    let catalog = packaged_command_catalog().expect("catalog");
    let command = command_for(&fixture);
    let snapshot = snapshot_for(&fixture);
    let observations =
        observations_from_native_evidence(&fixture["payload"], &catalog, &command, &snapshot)
            .expect("materialize");
    observations
        .iter()
        .map(|obs| {
            (
                obs.extension_id.clone(),
                obs.rule_id.clone(),
                obs.rule_severity.clone(),
                obs.rule_default_mode.clone(),
                obs.uncertainty_reasons
                    .iter()
                    .map(|u| u.as_str().to_owned())
                    .collect::<Vec<_>>(),
                obs.safe_variants
                    .iter()
                    .map(|v| v.variant_id.clone())
                    .collect::<Vec<_>>(),
                obs.matcher_evidence.len(),
            )
        })
        .collect()
}

#[test]
fn oracle_git_status_disabled_low() {
    // Python oracle: git.status, unc=[], sv=[], me=1, sev=low, mode=disabled.
    assert_eq!(
        summarize("nce_3994296943931012676.json"),
        vec![(
            "command.git".to_owned(),
            "command.git.status".to_owned(),
            "low".to_owned(),
            "disabled".to_owned(),
            Vec::<String>::new(),
            Vec::<String>::new(),
            1usize,
        )]
    );
}

#[test]
fn oracle_rm_rf_two_observations_one_uncertainty() {
    // Python oracle: filesystem.recursive-delete (no unc) +
    // shell-mutations.destructive-shell (matcher-failure).
    assert_eq!(
        summarize("nce_7188006403373633703.json"),
        vec![
            (
                "command.filesystem".to_owned(),
                "command.filesystem.recursive-delete".to_owned(),
                "high".to_owned(),
                "review".to_owned(),
                Vec::<String>::new(),
                Vec::<String>::new(),
                1usize,
            ),
            (
                "command.shell-mutations".to_owned(),
                "command.shell-mutations.destructive-shell".to_owned(),
                "high".to_owned(),
                "review".to_owned(),
                vec!["unsupported-input".to_owned()],
                Vec::<String>::new(),
                1usize,
            ),
        ]
    );
}

#[test]
fn oracle_aws_help_safe_variant() {
    // Python oracle: cloud.aws.resource-deletion, sv=["help"], me=1,
    // sev=critical, mode=review.
    assert_eq!(
        summarize("nce_64906308918362792.json"),
        vec![(
            "command.cloud.aws".to_owned(),
            "command.cloud.aws.resource-deletion".to_owned(),
            "critical".to_owned(),
            "review".to_owned(),
            Vec::<String>::new(),
            vec!["help".to_owned()],
            1usize,
        )]
    );
}

#[test]
fn oracle_kubectl_secret_read_uncertainty() {
    // Python oracle: delete-resources (no unc) + secret-read (unsupported-input).
    assert_eq!(
        summarize("nce_7436786547861050890.json"),
        vec![
            (
                "command.kubernetes-operations".to_owned(),
                "command.kubernetes-operations.delete-resources".to_owned(),
                "high".to_owned(),
                "review".to_owned(),
                Vec::<String>::new(),
                Vec::<String>::new(),
                1usize,
            ),
            (
                "command.kubernetes-secrets".to_owned(),
                "command.kubernetes-secrets.secret-read".to_owned(),
                "high".to_owned(),
                "review".to_owned(),
                vec!["unsupported-input".to_owned()],
                Vec::<String>::new(),
                1usize,
            ),
        ]
    );
}

#[test]
fn oracle_python_env_secret_read_uncertainty() {
    assert_eq!(
        summarize("nce_3760887278847525440.json"),
        vec![(
            "command.shell-mutations".to_owned(),
            "command.shell-mutations.process-environment-secret-read".to_owned(),
            "high".to_owned(),
            "review".to_owned(),
            vec!["unsupported-input".to_owned()],
            Vec::<String>::new(),
            1usize,
        )]
    );
}

// --- Binding / validator failure paths (Python raises; Rust returns Err) ---

#[test]
fn binding_catalog_digest_mismatch_rejected() {
    let mut fixture = fixture("nce_3994296943931012676.json");
    fixture["payload"]["command_extensions"]["binding"]["catalog_digest"] =
        Value::String("0".repeat(64));
    let catalog = packaged_command_catalog().expect("catalog");
    let command = command_for(&fixture);
    let snapshot = snapshot_for(&fixture);
    let result =
        observations_from_native_evidence(&fixture["payload"], &catalog, &command, &snapshot);
    assert_eq!(
        result.unwrap_err(),
        "native_command_extension_evidence_binding_mismatch"
    );
}

#[test]
fn binding_control_revision_mismatch_rejected() {
    let mut fixture = fixture("nce_3994296943931012676.json");
    let snapshot_value = &mut fixture["snapshot"];
    snapshot_value["revision"] = Value::from(999_999_u64);
    let catalog = packaged_command_catalog().expect("catalog");
    let command = command_for(&fixture);
    let snapshot = snapshot_for(&fixture);
    let result =
        observations_from_native_evidence(&fixture["payload"], &catalog, &command, &snapshot);
    assert_eq!(
        result.unwrap_err(),
        "native_command_extension_evidence_binding_mismatch"
    );
}

#[test]
fn command_model_mismatch_rejected() {
    let mut fixture = fixture("nce_3994296943931012676.json");
    // Build the command from the *unmutated* normalized_text, then tamper the
    // envelope so they diverge.
    let command = command_for(&fixture);
    fixture["payload"]["command_model"]["normalized_text"] =
        Value::String("git push --force".to_owned());
    let catalog = packaged_command_catalog().expect("catalog");
    let snapshot = snapshot_for(&fixture);
    let result =
        observations_from_native_evidence(&fixture["payload"], &catalog, &command, &snapshot);
    assert_eq!(
        result.unwrap_err(),
        "native_command_extension_evidence_command_mismatch"
    );
}

#[test]
fn tampered_observations_digest_rejected() {
    let mut fixture = fixture("nce_3994296943931012676.json");
    // Mutate an observation without recomputing the receipt digest → the
    // validator must reject (observations_digest no longer matches).
    fixture["payload"]["command_extensions"]["observations"][0]["rule_id"] =
        Value::String("command.git.other-rule".to_owned());
    assert!(
        validate_native_command_observations(&fixture["payload"]["command_extensions"]).is_none(),
        "tampered observation must fail receipt-digest recompute"
    );
}

#[test]
fn invalid_executable_rejected() {
    let mut fixture = fixture("nce_3994296943931012676.json");
    // Executable violating the regex must fail `_evidence_indexes`.
    fixture["payload"]["command_extensions"]["observations"][0]["matcher_evidence"][0]
        ["executable"] = Value::String("bad exec!".to_owned());
    assert!(
        validate_native_command_observations(&fixture["payload"]["command_extensions"]).is_none()
    );
}

#[test]
fn non_string_executable_rejected() {
    let mut fixture = fixture("nce_3994296943931012676.json");
    // `executable: 1` (non-null non-string) must fail — Option<String>
    // deserialization would collapse this; the Value-level check does not.
    fixture["payload"]["command_extensions"]["observations"][0]["matcher_evidence"][0]
        ["executable"] = Value::from(1);
    assert!(
        validate_native_command_observations(&fixture["payload"]["command_extensions"]).is_none()
    );
}

// Malformed-wire and redaction vectors for the strict validator, built on a
// minimal synthetic payload rather than a captured fixture.

fn wire_evidence(segment_index: u64) -> Value {
    serde_json::json!({
        "segment_index": segment_index,
        "executable": "ollama",
        "detail": "Matched bounded structured command constraints.",
    })
}

fn rehash(value: &mut Value) {
    let mut receipt = serde_json::Map::new();
    for key in [
        "observations",
        "permission_observations",
        "evaluation_error",
    ] {
        receipt.insert(key.to_owned(), value[key].clone());
    }
    let canonical = serde_json::to_string(&Value::Object(receipt)).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"hol-guard.native-command-observations.v1\x00");
    hasher.update(canonical.as_bytes());
    value["binding"]["observations_digest"] = Value::String(format!("{:x}", hasher.finalize()));
}

fn wire_observations() -> Value {
    let mut value = serde_json::json!({
        "schema": "guard.native-command-observations.v1",
        "binding": {
            "schema": "guard.native-command-receipt-binding.v1",
            "program_digest": "a".repeat(64),
            "catalog_digest": "b".repeat(64),
            "trust_digest": "c".repeat(64),
            "control_revision": 3,
            "managed_control_revision": 5,
            "control_effective_digest": "d".repeat(64),
            "observations_digest": "",
            "observation_count": 1,
            "uncertainty_count": 0,
        },
        "observations": [{
            "extension_id": "command.ollama",
            "extension_version": "1.0.0",
            "rule_id": "command.ollama.push",
            "rule_version": "1.0.0",
            "match_class": "unsafe",
            "match_classes": ["unsafe"],
            "matcher_evidence": [wire_evidence(0)],
            "safe_variants": [],
            "uncertainty_reasons": [],
            "effective_segment_indexes": [0],
        }],
        "permission_observations": [],
        "evaluation_error": null,
    });
    rehash(&mut value);
    value
}

#[test]
fn wire_observations_baseline_is_valid() {
    assert!(validate_native_command_observations(&wire_observations()).is_some());
}

#[test]
fn untrusted_evidence_is_rejected_even_with_recomputed_digest() {
    let cases = [
        ("segment_index", Value::Bool(true)),
        ("segment_index", Value::from(128)),
        ("segment_index", Value::from(-1)),
        ("executable", Value::from("/private/ollama")),
        ("executable", Value::from("secret token")),
        ("detail", Value::from("raw secret command")),
    ];
    for (field, replacement) in cases {
        let mut value = wire_observations();
        value["observations"][0]["matcher_evidence"][0][field] = replacement.clone();
        rehash(&mut value);
        assert!(
            validate_native_command_observations(&value).is_none(),
            "{field}={replacement} must be rejected"
        );
    }
}

#[test]
fn safe_variant_suppression_is_exact_and_cannot_hide_other_segments() {
    let mut value = wire_observations();
    {
        let item = &mut value["observations"][0];
        item["matcher_evidence"]
            .as_array_mut()
            .unwrap()
            .push(wire_evidence(1));
        item["safe_variants"] = serde_json::json!([{
            "match_class": "safe-variant",
            "variant_id": "help",
            "matcher_evidence": [wire_evidence(0)],
        }]);
        item["effective_segment_indexes"] = serde_json::json!([1]);
    }
    rehash(&mut value);
    assert!(validate_native_command_observations(&value).is_some());
    value["observations"][0]["effective_segment_indexes"] = serde_json::json!([]);
    rehash(&mut value);
    assert!(validate_native_command_observations(&value).is_none());
}

#[test]
fn permission_only_evidence_and_uncertainty_cannot_disappear() {
    let mut value = wire_observations();
    let mut evidence = wire_evidence(0);
    evidence["executable"] = Value::from("gh");
    value["permission_observations"] = serde_json::json!([{
        "extension_id": "command.github",
        "permission_id": "command.github.permission.read-remote",
        "matcher_evidence": [evidence],
        "uncertainty_reasons": ["matcher-failure"],
    }]);
    value["binding"]["observation_count"] = Value::from(2);
    value["binding"]["uncertainty_count"] = Value::from(1);
    rehash(&mut value);
    assert!(validate_native_command_observations(&value).is_some());
    value["binding"]["uncertainty_count"] = Value::from(0);
    assert!(validate_native_command_observations(&value).is_none());
    value["binding"]["uncertainty_count"] = Value::from(1);
    value["permission_observations"][0]["permission_id"] =
        Value::from("command.ollama.permission.push");
    rehash(&mut value);
    assert!(validate_native_command_observations(&value).is_none());
}

#[test]
fn unknown_fields_duplicates_limits_and_unbound_error_reject() {
    let original = wire_observations();

    let mut unknown = original.clone();
    unknown["raw_command"] = Value::from("secret");
    assert!(validate_native_command_observations(&unknown).is_none());

    let mut duplicated = original.clone();
    let observation = duplicated["observations"][0].clone();
    duplicated["observations"]
        .as_array_mut()
        .unwrap()
        .push(observation);
    duplicated["binding"]["observation_count"] = Value::from(2);
    rehash(&mut duplicated);
    assert!(validate_native_command_observations(&duplicated).is_none());

    let mut over_budget = original.clone();
    over_budget["observations"][0]["matcher_evidence"] =
        Value::Array(vec![wire_evidence(0); 8_193]);
    rehash(&mut over_budget);
    assert!(validate_native_command_observations(&over_budget).is_none());

    let mut unbound_error = original;
    unbound_error["evaluation_error"] = Value::from("native_command_evaluation_failed");
    rehash(&mut unbound_error);
    assert!(validate_native_command_observations(&unbound_error).is_none());
}
