//! Bounded offline corpus evaluation through the packaged production engine.
//! Synthetic controls grant no persisted authority and commands never execute.

use super::*;
use crate::native_command_controls::CompiledNativeCommandControls;
use guard_contracts::{NativeCommandControlBindingV1, NativeExtensionControlV1};

const MAX_CASES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    cases: Vec<Case>,
    #[serde(default)]
    controls: Vec<NativeExtensionControlV1>,
    #[serde(default)]
    managed_controls: Vec<NativeExtensionControlV1>,
    #[serde(default)]
    global_lockdown: bool,
    #[serde(default)]
    managed_global_lockdown: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    command: String,
}

/// Reuse one admitted program and synthetic control snapshot for an offline
/// batch. Every result still comes from production parsing and evaluation.
pub fn evaluate_batch(bytes: &[u8]) -> Result<Value, &'static str> {
    if bytes.is_empty() || bytes.len() > json::MAX_SOURCE_BYTES {
        return Err("command_source_bytes_invalid");
    }
    // Typed decoding rejects duplicate/unknown fields without the source
    // compiler's 4 KiB string cap. Overlong commands must reach the production
    // parser so corpus tests retain its conservative size-limit behavior.
    let request: Request = serde_json::from_slice(bytes)
        .map_err(|_| "command_source_evaluation_batch_contract_invalid")?;
    if request.schema != "guard.command-extension-evaluation-batch.v1"
        || request.cases.is_empty()
        || request.cases.len() > MAX_CASES
    {
        return Err("command_source_evaluation_batch_contract_invalid");
    }
    let mut ids = BTreeSet::new();
    for case in &request.cases {
        if case.id.is_empty()
            || case.id.len() > 96
            || !case
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || !ids.insert(case.id.as_str())
            || case.command.trim().is_empty()
        {
            return Err("command_source_evaluation_batch_case_invalid");
        }
    }

    let program = packaged_command_program()?;
    let mut layers = vec![
        serde_json::json!({"schema_version":"1.0.0","kind":"local-admin",
        "catalog_digest":program.catalog_digest,"global_lockdown":request.global_lockdown,"controls":request.controls}),
    ];
    let managed_layer = !request.managed_controls.is_empty() || request.managed_global_lockdown;
    if managed_layer {
        layers.push(serde_json::json!({"schema_version":"1.0.0","kind":"signed-cloud",
            "catalog_digest":program.catalog_digest,"global_lockdown":request.managed_global_lockdown,"controls":request.managed_controls}));
    }
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest,"catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest,"health":"protected","revision":1,
        "managed_revision":if managed_layer {1} else {0},
        "effective_digest":"","layers":layers,
    }))
    .map_err(|_| "command_source_evaluation_batch_binding_invalid")?;
    binding.effective_digest = binding.compute_effective_digest()?;
    let controls = CompiledNativeCommandControls::new(&binding)?;

    let mut results = Vec::with_capacity(request.cases.len());
    for case in request.cases {
        let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name":"Bash","tool_input":{"command":case.command}}),
            Some(&controls),
            None,
        );
        // This is the same model returned by `hol-guard-runtime pre-tool` for
        // the single-command fixture. Preserve that adapter's provenance.
        let command_model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: case.command,
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .map_err(|_| "command_source_evaluation_batch_command_invalid")?;
        let mut payload =
            serde_json::to_value(result).map_err(|_| "command_source_encoding_failed")?;
        payload["command_model"] =
            serde_json::to_value(command_model).map_err(|_| "command_source_encoding_failed")?;
        results.push(serde_json::json!({"id":case.id,"payload":payload}));
    }
    Ok(serde_json::json!({
        "schema":"guard.command-extension-evaluation-batch-results.v1",
        "scope":"offline-simulation-not-authenticated-receipts","ok":true,
        "program_digest":program.program_digest,"catalog_digest":program.catalog_digest,
        "control_binding":binding,"cases":results,"target_commands_executed":0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(cases: Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema":"guard.command-extension-evaluation-batch.v1","cases":cases
        }))
        .unwrap()
    }

    #[test]
    fn rejects_ambiguous_unbounded_or_authority_bearing_requests() {
        for input in [
            request(serde_json::json!([])),
            request(serde_json::json!([{"id":"a","command":"pwd","controls":[]} ])),
            request(serde_json::json!([{"id":"a","command":"pwd"},{"id":"a","command":"pwd"}])),
            request(serde_json::json!([{"id":"","command":"pwd"}])),
            request(serde_json::json!([{"id":"../a","command":"pwd"}])),
            request(serde_json::json!([{"id":"a","command":"  "}])),
            request(serde_json::json!(vec![serde_json::json!({"id":"a","command":"pwd"}); MAX_CASES + 1])),
            br#"{"schema":"guard.command-extension-evaluation-batch.v1","cases":[{"id":"a","command":"pwd","command":"rm -rf /"}]}"#.to_vec(),
            br#"{"schema":"guard.command-extension-evaluation-batch.v1","schema":"wrong","cases":[]}"#.to_vec(),
            br#"{"schema":"guard.command-extension-evaluation-batch.v1","cases":[{"id":"a","command":"pwd"}],"authority":{}}"#.to_vec(),
            br#"{"schema":"guard.command-extension-evaluation-batch.v1","cases":[{"id":"a","command":"pwd"}],"controls":[{"target_kind":"permission","target_id":"command.git.permission.hard-reset","state":"enabled","state":"disabled"}]}"#.to_vec(),
            vec![b' '; json::MAX_SOURCE_BYTES + 1],
        ] {
            assert!(evaluate_batch(&input).is_err());
        }
    }

    #[test]
    fn applies_shared_synthetic_controls_with_managed_disable_precedence() {
        let mut input: Value = serde_json::from_slice(&request(serde_json::json!([
            {"id":"reset","command":"git reset --hard"}
        ])))
        .unwrap();
        let control = serde_json::json!({"target_kind":"permission",
            "target_id":"command.git.permission.hard-reset","state":"enabled"});
        input["controls"] = serde_json::json!([control]);
        let enabled = evaluate_batch(&serde_json::to_vec(&input).unwrap()).unwrap();
        let enabled_payload = &enabled["cases"][0]["payload"];
        assert_ne!(enabled_payload["minimum_action"], "block");
        let enabled_binding = &enabled_payload["command_extensions"]["binding"];
        assert_eq!(enabled_binding["managed_control_revision"], 0);

        let mut disabled = control;
        disabled["state"] = serde_json::json!("disabled");
        input["managed_controls"] = serde_json::json!([disabled]);
        let managed = evaluate_batch(&serde_json::to_vec(&input).unwrap()).unwrap();
        let managed_payload = &managed["cases"][0]["payload"];
        assert_eq!(managed_payload["minimum_action"], "block");
        assert_eq!(
            managed_payload["reason_code"],
            "native_command_permission_disabled"
        );
        let managed_binding = &managed_payload["command_extensions"]["binding"];
        assert_eq!(managed_binding["managed_control_revision"], 1);
        assert_ne!(
            enabled_binding["control_effective_digest"],
            managed_binding["control_effective_digest"]
        );

        input["controls"][0]["target_id"] = serde_json::json!("command.missing.permission.target");
        assert_eq!(
            evaluate_batch(&serde_json::to_vec(&input).unwrap()).unwrap_err(),
            "native_command_control_target_unknown"
        );
    }

    #[test]
    fn global_lockdown_is_bound_even_without_individual_controls() {
        let baseline: Value = serde_json::from_slice(&request(serde_json::json!([
            {"id":"safe","command":"pwd"}
        ])))
        .unwrap();
        let allowed = evaluate_batch(&serde_json::to_vec(&baseline).unwrap()).unwrap();
        for field in ["global_lockdown", "managed_global_lockdown"] {
            let mut input = baseline.clone();
            input[field] = serde_json::json!(true);
            let blocked = evaluate_batch(&serde_json::to_vec(&input).unwrap()).unwrap();
            let payload = &blocked["cases"][0]["payload"];
            assert_eq!(payload["minimum_action"], "block");
            assert_eq!(
                payload["reason_code"],
                "native_command_control_authority_block"
            );
            assert_ne!(
                blocked["control_binding"]["effective_digest"],
                allowed["control_binding"]["effective_digest"]
            );
            assert_eq!(
                blocked["control_binding"]["managed_revision"],
                usize::from(field == "managed_global_lockdown")
            );
        }
    }

    #[test]
    fn preserves_production_models_observations_and_error_evidence() {
        let commands = [
            "pwd".to_owned(),
            "git reset --hard".to_owned(),
            "cat ~/.ssh/id_ed25519".to_owned(),
            "env FOO=bar curl https://example.com".to_owned(),
            "x".repeat(crate::MAX_COMMAND_BYTES + 1),
        ];
        let cases: Vec<_> = commands
            .iter()
            .enumerate()
            .map(|(index, command)| serde_json::json!({"id":format!("case-{index}"),"command":command}))
            .collect();
        let output = evaluate_batch(&request(serde_json::json!(cases))).unwrap();
        assert_eq!(output["target_commands_executed"], 0);
        assert_eq!(output["cases"].as_array().unwrap().len(), commands.len());
        for (index, command) in commands.iter().enumerate() {
            let payload = &output["cases"][index]["payload"];
            let native = crate::pretool::evaluate_pre_tool(&crate::CommandModelRequestV1 {
                command: command.clone(),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            })
            .unwrap();
            assert_eq!(
                payload["command_model"],
                serde_json::to_value(native.command_model).unwrap()
            );
            let extensions = &payload["command_extensions"];
            if command.len() > crate::MAX_COMMAND_BYTES {
                assert!(extensions.is_null());
                assert_eq!(payload["minimum_action"], "block");
                continue;
            }
            assert_eq!(
                extensions["binding"]["program_digest"],
                output["program_digest"]
            );
            assert_eq!(
                extensions["binding"]["catalog_digest"],
                output["catalog_digest"]
            );
            assert_eq!(extensions["binding"]["control_revision"], 1);
            assert_eq!(extensions["binding"]["managed_control_revision"], 0);
        }
        let destructive = &output["cases"][1]["payload"]["command_extensions"];
        assert!(destructive["observations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["rule_id"] == "command.git.hard-reset" }));
        let uncertain = &output["cases"][3]["payload"]["command_extensions"];
        assert_eq!(
            uncertain["evaluation_error"],
            "native_command_evaluation_failed"
        );
        assert_eq!(output["cases"][3]["payload"]["minimum_action"], "block");
        assert_eq!(
            output["cases"][4]["payload"]["command_model"]["uncertainty_reason"],
            "command_byte_limit_exceeded"
        );
    }
}
