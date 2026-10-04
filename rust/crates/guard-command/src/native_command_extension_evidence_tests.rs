//! Parity tests for `native_command_extension_evidence` against real
//! `native-command-observations.v1` payloads captured from the packaged
//! native evaluator, and the Python `observations_from_native_evidence`
//! oracle. Each fixture JSON carries `{payload, snapshot, command}`; the
//! `payload` is the full `native_extension_evidence` envelope the resident
//! `evaluate_command` receives.

use serde_json::Value;
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
                vec!["matcher-failure".to_owned()],
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
    // Python oracle: delete-resources (no unc) + secret-read (matcher-failure).
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
                vec!["matcher-failure".to_owned()],
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
            vec!["matcher-failure".to_owned()],
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
