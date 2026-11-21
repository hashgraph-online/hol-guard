//! Bridge captured attribution to the existing package intelligence evaluator.
//! A reputation assessment is not installed-code integrity or execution consent.

use std::collections::BTreeSet;

use guard_command::package_intent_common::{
    build_package_request_artifact, js_target, PackageIntent,
};
use guard_contracts::{NativeBashHostV1, NativeBashSubjectV1, NativeScriptPackageStateV1};
use serde_json::{json, Value};

pub(super) fn build(
    subject: &NativeBashSubjectV1,
    harness: &str,
) -> Result<Option<Value>, &'static str> {
    subject.validate()?;
    if !matches!(
        (subject.context.host, harness),
        (NativeBashHostV1::OmpInputRewriteV1, "omp") | (NativeBashHostV1::PiInputMutationV1, "pi")
    ) {
        return Err("native_bash_dependency_harness_mismatch");
    }
    if subject.package_bindings.is_empty()
        || subject
            .package_bindings
            .iter()
            .any(|package| package.state != NativeScriptPackageStateV1::Declared)
    {
        // An empty or partial observation must never reach the evaluator's
        // empty-material allow result and masquerade as verified intelligence.
        return Ok(None);
    }
    let subject_hash = subject.identity_sha256()?;
    let mut specs = BTreeSet::new();
    let mut code_hashes = BTreeSet::new();
    for package in &subject.package_bindings {
        let name = package
            .name
            .as_deref()
            .ok_or("native_bash_dependency_identity_missing")?;
        let version = package
            .version
            .as_deref()
            .ok_or("native_bash_dependency_identity_missing")?;
        specs.insert(format!("{name}@{version}"));
        for index in &package.code_input_indices {
            code_hashes.insert(
                subject.code_inputs[usize::from(*index)]
                    .content_sha256
                    .clone(),
            );
        }
    }
    let intent = PackageIntent {
        package_manager: "npm".into(),
        intent_kind: "execute",
        command_tokens: vec!["captured-dependency-check".into()],
        redacted_command: "Captured Bash dependency assessment".into(),
        targets: specs.iter().map(|spec| js_target(spec)).collect(),
        manifest_paths: Vec::new(),
        lockfile_paths: Vec::new(),
        flags: Vec::new(),
        notes: Vec::new(),
        local_executions: Vec::new(),
        execution_context_hashes: vec![subject_hash.clone()],
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
        // The captured attribution carries no manifest, lockfile or
        // installed-package read, so nothing here establishes that a
        // runner is already bound to local project state. Claiming it
        // would suppress the review artifact on unread evidence.
        routine_local_runner: false,
    };
    let mut artifact =
        build_package_request_artifact(harness, &intent, "captured-script-dependencies", "project");
    artifact.artifact_id = format!("{harness}:project:package-request:{subject_hash}");
    artifact.name = "Declared packages used by captured Bash".into();
    artifact.metadata["assessment_only"] = json!(true);
    artifact.metadata["captured_subject_sha256"] = json!(subject_hash);
    artifact.metadata["captured_code_sha256"] = json!(code_hashes);
    artifact.metadata["dependency_evidence_kind"] = json!("declared_package_reputation");
    Ok(Some(artifact.to_dict()))
}
