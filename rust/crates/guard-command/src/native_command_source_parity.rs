//! Development-only offline comparison through the production native evaluator.
//! Synthetic controls are never persisted, authenticated, or published.
use super::*;
use crate::native_command_controls::CompiledNativeCommandControls;
use guard_contracts::{NativeCommandControlBindingV1, PreToolResultV1};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    baseline_program: Value,
    build: Value,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    payload: Value,
    controls: Vec<Value>,
    #[serde(default)]
    managed_controls: Vec<Value>,
}

fn evaluate(
    program: Arc<NativeCommandProgram>,
    case: &Case,
) -> Result<PreToolResultV1, &'static str> {
    let mut layers = vec![
        serde_json::json!({"schema_version":"1.0.0","kind":"local-admin",
        "catalog_digest":program.catalog_digest,"global_lockdown":false,"controls":case.controls}),
    ];
    if !case.managed_controls.is_empty() {
        layers.push(serde_json::json!({"schema_version":"1.0.0","kind":"signed-cloud",
            "catalog_digest":program.catalog_digest,"global_lockdown":false,"controls":case.managed_controls}));
    }
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema":"guard.native-command-control-binding.v1","program_digest":program.program_digest,
        "catalog_digest":program.catalog_digest,"trust_digest":program.trust_digest,"health":"protected",
        "revision":1,"managed_revision":if case.managed_controls.is_empty() {0} else {1},
        "effective_digest":"","layers":layers
    })).map_err(|_| "command_source_parity_binding_invalid")?;
    binding.effective_digest = binding.compute_effective_digest()?;
    let controls = CompiledNativeCommandControls::for_program(&binding, program)?;
    Ok(crate::pretool::evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &case.payload,
        Some(&controls),
        None,
    ))
}

fn normalized(mut result: PreToolResultV1) -> PreToolResultV1 {
    // Only these three authority identities intentionally change in migration.
    // Compare every decision, reason, observation, segment, evidence, count, and
    // observation digest. This does NOT test authenticated approval continuity.
    if let Some(extensions) = result.command_extensions.as_mut() {
        extensions.binding.program_digest.clear();
        extensions.binding.catalog_digest.clear();
        extensions.binding.control_effective_digest.clear();
    }
    result
}

pub fn compare_programs(bytes: &[u8]) -> Result<Value, &'static str> {
    let request: Request = serde_json::from_value(json::decode(bytes)?)
        .map_err(|_| "command_source_parity_contract_invalid")?;
    if request.schema != "guard.command-extension-parity.v1"
        || request.cases.is_empty()
        || request.cases.len() > 256
    {
        return Err("command_source_parity_contract_invalid");
    }
    let baseline = Arc::new(NativeCommandProgram::from_packaged_bytes(
        &serde_json::to_vec(&request.baseline_program)
            .map_err(|_| "command_source_encoding_failed")?,
    )?);
    let compiled = compile_build_request(
        &serde_json::to_vec(&request.build).map_err(|_| "command_source_encoding_failed")?,
    )?;
    let candidate = Arc::new(NativeCommandProgram::from_packaged_bytes(
        &serde_json::to_vec(&compiled.program).map_err(|_| "command_source_encoding_failed")?,
    )?);
    let mut ids = BTreeSet::new();
    let mut results = Vec::new();
    for case in request.cases {
        if case.id.is_empty() || case.id.len() > 96 || !ids.insert(case.id.clone()) {
            return Err("command_source_parity_case_invalid");
        }
        let before = normalized(evaluate(Arc::clone(&baseline), &case)?);
        let after = normalized(evaluate(Arc::clone(&candidate), &case)?);
        let mut raw_before = None;
        let mut raw_after = None;
        let raw_scope = if let Some(command) = case
            .payload
            .pointer("/tool_input/command")
            .or_else(|| case.payload.get("command"))
            .and_then(Value::as_str)
        {
            let request: crate::CommandModelRequestV1 =
                serde_json::from_value(serde_json::json!({"command":command}))
                    .map_err(|_| "command_source_parity_command_invalid")?;
            if let Ok(command) = crate::parse_command(&request) {
                let active = baseline
                    .extensions
                    .iter()
                    .map(|extension| extension.extension_id.clone())
                    .collect();
                // Coverage must not be masked by an unrelated compatibility
                // observer rejecting a command model that declarative rules
                // support. The full production path is compared above.
                raw_before = Some(baseline.observe_declarative(&command, &active, None));
                let active = candidate
                    .extensions
                    .iter()
                    .map(|extension| extension.extension_id.clone())
                    .collect();
                raw_after = Some(candidate.observe_declarative(&command, &active, None));
                "all-extensions-raw-declarative-observations-independent-of-controls"
            } else {
                "not-evaluated-parser-rejected-command"
            }
        } else {
            "not-applicable-non-command-payload"
        };
        let passed = before == after && raw_before == raw_after;
        let mut rules: BTreeSet<_> = before
            .command_extensions
            .iter()
            .flat_map(|batch| &batch.observations)
            .map(|row| row.rule_id.clone())
            .collect();
        rules.extend(
            raw_before
                .iter()
                .filter_map(|result| result.as_ref().ok())
                .flat_map(|batch| &batch.observations)
                .map(|row| row.rule_id.clone()),
        );
        let permissions: BTreeSet<_> = before
            .command_extensions
            .iter()
            .flat_map(|batch| &batch.permission_observations)
            .map(|row| row.permission_id.clone())
            .collect();
        results.push(serde_json::json!({"id":case.id,"passed":passed,
            "observed_rules":rules,"observed_permissions":permissions,
            "raw_scope":raw_scope,
            "raw_evaluation_error":raw_before.as_ref().and_then(|result| result.as_ref().err()),
            "raw_baseline":if passed {Value::Null} else {serde_json::to_value(raw_before).unwrap()},
            "raw_candidate":if passed {Value::Null} else {serde_json::to_value(raw_after).unwrap()},
            "baseline":if passed {Value::Null} else {serde_json::to_value(before).unwrap()},
            "candidate":if passed {Value::Null} else {serde_json::to_value(after).unwrap()}}));
    }
    Ok(
        serde_json::json!({"schema":"guard.command-extension-parity-results.v1",
        "scope":"same-native-engine-two-programs-offline-not-authenticated-receipts",
        "ok":results.iter().all(|case| case["passed"] == true),"cases":results,
        "baseline_program_digest":baseline.program_digest,"candidate_program_digest":candidate.program_digest,
        "implementation_digest":compiled.implementation_digest,"target_commands_executed":0,
        "excluded_identity_fields":["binding.program_digest","binding.catalog_digest","binding.control_effective_digest"]}),
    )
}
