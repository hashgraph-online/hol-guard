//! Offline author fixtures use production evaluation with synthetic controls.
//! No execution, persistence, authenticated authority, or receipt generation.

use super::*;
use crate::native_command_controls::CompiledNativeCommandControls;
use guard_contracts::NativeCommandControlBindingV1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRequest {
    schema: String,
    build: Value,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    command: String,
    enabled_extensions: Vec<String>,
    disabled_permissions: Vec<String>,
    expected_action: String,
    rule_id: String,
    expected_effective_segments: Vec<usize>,
}

/// Run bounded source-author fixtures without granting any runtime authority.
pub fn run_fixtures(bytes: &[u8]) -> Result<Value, &'static str> {
    let request: FixtureRequest = serde_json::from_value(json::decode(bytes)?)
        .map_err(|_| "command_source_fixture_contract_invalid")?;
    if request.schema != "guard.command-extension-fixtures.v1"
        || request.cases.is_empty()
        || request.cases.len() > 256
    {
        return Err("command_source_fixture_contract_invalid");
    }
    let output = compile_build_request(
        &serde_json::to_vec(&request.build).map_err(|_| "command_source_encoding_failed")?,
    )?;
    let program = Arc::new(NativeCommandProgram::from_packaged_bytes(
        &serde_json::to_vec(&output.program).map_err(|_| "command_source_encoding_failed")?,
    )?);
    let mut ids = BTreeSet::new();
    let mut results = Vec::new();
    for case in request.cases {
        if case.id.is_empty()
            || case.id.len() > 96
            || !case
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !ids.insert(case.id.clone())
            || !matches!(case.expected_action.as_str(), "allow" | "review" | "block")
            || !program
                .rules
                .iter()
                .any(|rule| rule.rule_id == case.rule_id)
            || case
                .expected_effective_segments
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err("command_source_fixture_case_invalid");
        }
        let mut targets = Vec::new();
        for (kind, state, values) in [
            ("extension", "enabled", &case.enabled_extensions),
            ("permission", "disabled", &case.disabled_permissions),
        ] {
            let mut seen = BTreeSet::new();
            for target in values {
                if !seen.insert(target) {
                    return Err("command_source_fixture_control_duplicate");
                }
                targets
                    .push(serde_json::json!({"target_kind":kind,"target_id":target,"state":state}));
            }
        }
        let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
            "schema":"guard.native-command-control-binding.v1",
            "program_digest":program.program_digest,"catalog_digest":program.catalog_digest,
            "trust_digest":program.trust_digest,"health":"protected","revision":1,
            "managed_revision":0,"effective_digest":"",
            "layers":[{"schema_version":"1.0.0","kind":"local-admin",
                "catalog_digest":program.catalog_digest,"global_lockdown":false,"controls":targets}]
        })).map_err(|_| "command_source_fixture_binding_invalid")?;
        binding.effective_digest = binding.compute_effective_digest()?;
        let controls = CompiledNativeCommandControls::for_program(&binding, Arc::clone(&program))?;
        let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name":"Bash","tool_input":{"command":case.command}}),
            Some(&controls),
            None,
        );
        // Extract observations emitted by the same production evaluation. Do
        // not parse or evaluate a second time to construct fixture evidence.
        let segments: BTreeSet<usize> = result
            .command_extensions
            .as_ref()
            .into_iter()
            .flat_map(|batch| &batch.observations)
            .filter(|row| row.rule_id == case.rule_id)
            .flat_map(|row| row.effective_segment_indexes.iter().copied())
            .collect();
        let actual: Vec<_> = segments.into_iter().collect();
        results.push(serde_json::json!({
            "id":case.id,"passed":result.minimum_action == case.expected_action
                && actual == case.expected_effective_segments,
            "actual_action":result.minimum_action,"expected_action":case.expected_action,
            "rule_id":case.rule_id,"actual_effective_segments":actual,
            "expected_effective_segments":case.expected_effective_segments,
        }));
    }
    Ok(serde_json::json!({
        "schema":"guard.command-extension-fixture-results.v1",
        "scope":"offline-simulation-not-authenticated-receipts",
        "ok":results.iter().all(|result| result["passed"] == true),
        "program_digest":program.program_digest,"cases":results,
        "target_commands_executed":0,
    }))
}
