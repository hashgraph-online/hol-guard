//! Real admission/evaluation controls for retired DNS identifiers.
use super::*;
use crate::native_command_control_projection::project_validated_layer;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::pretool::evaluate_pre_tool_envelope_with_extensions;
use guard_contracts::{
    NativeCommandControlBindingV1, NativeExtensionControlLayerV1, NativeExtensionControlV1,
    NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
};

const PROVIDERS: [(&str, &str, &str); 3] = [
    (
        "command.dns.aws",
        "command.dns.aws.permission.zone-deletion",
        "aws route53 delete-hosted-zone --id Z123",
    ),
    (
        "command.dns.gcp",
        "command.dns.gcp.permission.zone-deletion",
        "gcloud dns managed-zones delete public",
    ),
    (
        "command.dns.azure",
        "command.dns.azure.permission.public-zone-deletion",
        "az network dns zone delete -g app -n example.test",
    ),
];

fn binding(controls: &[(&str, &str, &str)], managed: bool) -> NativeCommandControlBindingV1 {
    let program = packaged_command_program().unwrap();
    let mut binding = NativeCommandControlBindingV1 {
        schema: NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.into(),
        authority: None,
        program_digest: program.program_digest.clone(),
        catalog_digest: program.catalog_digest.clone(),
        trust_digest: program.trust_digest.clone(),
        health: "protected".into(),
        revision: 4,
        managed_revision: 7,
        effective_digest: String::new(),
        layers: vec![NativeExtensionControlLayerV1 {
            schema_version: "1.0.0".into(),
            kind: if managed {
                "signed-cloud"
            } else {
                "local-admin"
            }
            .into(),
            catalog_digest: program.catalog_digest.clone(),
            global_lockdown: false,
            controls: controls
                .iter()
                .map(|(kind, target, state)| NativeExtensionControlV1 {
                    target_kind: (*kind).into(),
                    target_id: (*target).into(),
                    state: (*state).into(),
                })
                .collect(),
        }],
    };
    resign(&mut binding);
    binding
}

fn resign(binding: &mut NativeCommandControlBindingV1) {
    binding.effective_digest = binding.compute_effective_digest().unwrap();
}

fn error(binding: &NativeCommandControlBindingV1, expected: &str) {
    assert_eq!(
        CompiledNativeCommandControls::new(binding).unwrap_err(),
        expected
    );
}

fn evaluate(binding: &NativeCommandControlBindingV1, command: &str) -> Value {
    let original = serde_json::to_vec(binding).unwrap();
    let controls = CompiledNativeCommandControls::new(binding).unwrap();
    let baseline = evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "pwd"}}),
        None,
        None,
    );
    assert_eq!(baseline.minimum_action, "allow");
    let model = crate::parse_command(
        &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
    )
    .unwrap();
    let result = controls.apply(&model, baseline, None);
    let receipt = &result.command_extensions.as_ref().unwrap().binding;
    assert_eq!(receipt.control_revision, binding.revision);
    assert_eq!(receipt.managed_control_revision, binding.managed_revision);
    assert_eq!(receipt.control_effective_digest, binding.effective_digest);
    assert_eq!(receipt.program_digest, binding.program_digest);
    assert_eq!(receipt.catalog_digest, binding.catalog_digest);
    assert_eq!(receipt.trust_digest, binding.trust_digest);
    assert_eq!(serde_json::to_vec(binding).unwrap(), original);
    let mut value = serde_json::to_value(result).unwrap();
    // Compare all decision/observation fields after separately checking the
    // intentionally different original raw identity of each equivalent input.
    value["command_extensions"]["binding"]["control_effective_digest"] = Value::Null;
    value
}

#[test]
fn dns_projection_aggregate_matches_explicit_provider_evaluation() {
    for (kind, aggregate) in [
        ("extension", "command.dns"),
        ("permission", "command.dns.permission.delete"),
    ] {
        for managed in [false, true] {
            for state in ["enabled", "disabled"] {
                let raw = binding(&[(kind, aggregate, state)], managed);
                let items: Vec<_> = PROVIDERS
                    .iter()
                    .map(|(extension, permission, _)| {
                        (
                            kind,
                            if kind == "extension" {
                                *extension
                            } else {
                                *permission
                            },
                            state,
                        )
                    })
                    .collect();
                let explicit = binding(&items, managed);
                assert_ne!(raw.effective_digest, explicit.effective_digest);
                for (_, _, command) in PROVIDERS {
                    let actual = evaluate(&raw, command);
                    assert_eq!(actual, evaluate(&explicit, command));
                    assert_eq!(
                        actual["minimum_action"],
                        if state == "disabled" {
                            "block"
                        } else if kind == "permission" {
                            "allow"
                        } else {
                            "review"
                        }
                    );
                }
                assert_eq!(evaluate(&raw, "pwd"), evaluate(&explicit, "pwd"));
            }
        }
    }
}

#[test]
fn dns_projection_unique_collisions_preserve_disable_dominance_and_other_providers() {
    for (kind, aggregate) in [
        ("extension", "command.dns"),
        ("permission", "command.dns.permission.delete"),
    ] {
        for managed in [false, true] {
            for (selected, (extension, permission, _)) in PROVIDERS.iter().enumerate() {
                let provider = if kind == "extension" {
                    *extension
                } else {
                    *permission
                };
                for (aggregate_state, provider_state) in
                    [("enabled", "disabled"), ("disabled", "enabled")]
                {
                    for reverse in [false, true] {
                        let mut controls = vec![
                            (kind, aggregate, aggregate_state),
                            (kind, provider, provider_state),
                        ];
                        if reverse {
                            controls.reverse();
                        }
                        let raw = binding(&controls, managed);
                        let explicit: Vec<_> = PROVIDERS
                            .iter()
                            .enumerate()
                            .map(|(index, (extension, permission, _))| {
                                (
                                    kind,
                                    if kind == "extension" {
                                        *extension
                                    } else {
                                        *permission
                                    },
                                    if index == selected {
                                        "disabled"
                                    } else {
                                        aggregate_state
                                    },
                                )
                            })
                            .collect();
                        let expected = binding(&explicit, managed);
                        for (_, _, command) in PROVIDERS {
                            assert_eq!(evaluate(&raw, command), evaluate(&expected, command));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn dns_projection_raw_validation_precedes_admission() {
    for (kind, aggregate, provider) in [
        ("extension", "command.dns", PROVIDERS[0].0),
        (
            "permission",
            "command.dns.permission.delete",
            PROVIDERS[0].1,
        ),
    ] {
        for target in [aggregate, provider] {
            for state in ["enabled", "disabled"] {
                for reverse in [false, true] {
                    let mut controls = vec![
                        (kind, aggregate, "enabled"),
                        (kind, provider, "disabled"),
                        (kind, target, state),
                    ];
                    if reverse {
                        controls.reverse();
                    }
                    let raw = binding(&controls, false);
                    assert_eq!(raw.validate(), Err("native_command_control_target_invalid"));
                    error(&raw, "native_command_control_target_invalid");
                }
            }
        }
    }
    let mut raw = binding(&[("extension", "command.dns", "disabled")], false);
    raw.effective_digest = "0".repeat(64);
    error(&raw, "native_command_control_digest_mismatch");
    resign(&mut raw);
    raw.layers.push(raw.layers[0].clone());
    resign(&mut raw);
    error(&raw, "native_command_control_layer_invalid");
    raw.layers.push(raw.layers[0].clone());
    error(&raw, "native_command_control_binding_invalid");
}

#[test]
fn dns_projection_recognizes_only_exact_kind_and_identifiers() {
    for (kind, target, expected) in [
        (
            "extension",
            "command.dnss",
            "native_command_control_target_unknown",
        ),
        (
            "extension",
            "command.dns.old",
            "native_command_control_target_unknown",
        ),
        (
            "permission",
            "command.dns.permission.deletes",
            "native_command_control_target_unknown",
        ),
        (
            "extension",
            "command.DNS",
            "native_command_control_target_invalid",
        ),
        (
            "extension",
            "command.dns.permission.delete",
            "native_command_control_target_invalid",
        ),
        (
            "permission",
            "command.dns",
            "native_command_control_target_invalid",
        ),
    ] {
        error(&binding(&[(kind, target, "disabled")], false), expected);
    }
    let mut raw = binding(&[("extension", "command.dns", "disabled")], false);
    raw.program_digest = "0".repeat(64);
    error(&raw, "native_command_program_binding_mismatch");
}

#[test]
fn dns_projection_cross_layer_and_global_authority_floors_stay_strict() {
    let mut raw = binding(
        &[("permission", "command.dns.permission.delete", "enabled")],
        false,
    );
    raw.layers.push(
        binding(&[("permission", PROVIDERS[0].1, "disabled")], true)
            .layers
            .remove(0),
    );
    resign(&mut raw);
    assert_eq!(evaluate(&raw, PROVIDERS[0].2)["minimum_action"], "block");
    assert_eq!(evaluate(&raw, PROVIDERS[1].2)["minimum_action"], "allow");
    raw.layers.reverse();
    resign(&mut raw);
    assert_eq!(evaluate(&raw, PROVIDERS[0].2)["minimum_action"], "block");
    for health in [
        "tampered",
        "recovery-required",
        "unenrolled",
        "degraded-unacknowledged",
        "degraded-acknowledged",
    ] {
        raw.health = health.into();
        resign(&mut raw);
        assert_eq!(evaluate(&raw, PROVIDERS[1].2)["minimum_action"], "block");
    }
    raw.health = "protected".into();
    raw.layers[0].global_lockdown = true;
    resign(&mut raw);
    assert_eq!(evaluate(&raw, "pwd")["minimum_action"], "block");
}

#[test]
fn dns_projection_raw_and_derived_bounds_remain_distinct() {
    for raw_count in [510, 511, 512, 513] {
        let mut raw = binding(&[("extension", "command.dns", "enabled")], false);
        for index in 1..raw_count {
            raw.layers[0].controls.push(NativeExtensionControlV1 {
                target_kind: "extension".into(),
                target_id: format!("command.synthetic{index}"),
                state: "disabled".into(),
            });
        }
        resign(&mut raw);
        if raw_count > 512 {
            error(&raw, "native_command_control_layer_invalid");
        } else {
            assert_eq!(raw.validate(), Ok(()));
            let projected = project_validated_layer(&raw.layers[0]);
            if raw_count == 510 {
                assert_eq!(projected.unwrap().len(), 512);
                error(&raw, "native_command_control_target_unknown");
            } else {
                assert_eq!(
                    projected.unwrap_err(),
                    "native_command_control_layer_invalid"
                );
                error(&raw, "native_command_control_layer_invalid");
            }
        }
    }
}

#[test]
fn dns_projection_permission_enable_still_requires_configurable_program_gate() {
    let mut program = NativeCommandProgram::from_packaged_bytes(EMBEDDED_PROGRAM).unwrap();
    program
        .extensions
        .iter_mut()
        .find(|extension| extension.extension_id == PROVIDERS[0].0)
        .unwrap()
        .permissions
        .iter_mut()
        .find(|permission| permission.permission_id == PROVIDERS[0].1)
        .unwrap()
        .configurable = false;
    let program = Arc::new(program);
    for target in ["command.dns.permission.delete", PROVIDERS[0].1] {
        let raw = binding(&[("permission", target, "enabled")], false);
        let controls = CompiledNativeCommandControls::for_program(&raw, program.clone()).unwrap();
        let baseline = evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "pwd"}}),
            None,
            None,
        );
        let model = crate::parse_command(
            &serde_json::from_value(serde_json::json!({"command": PROVIDERS[0].2})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            controls.apply(&model, baseline, None).minimum_action,
            "review"
        );
    }
}

#[test]
fn dns_projection_missing_provider_catalog_target_is_rejected() {
    // Vary the real compiled catalog through the existing crate-local seam;
    // production always admits only its exact packaged program.
    let mut program = NativeCommandProgram::from_packaged_bytes(EMBEDDED_PROGRAM).unwrap();
    program
        .extensions
        .retain(|extension| extension.extension_id != PROVIDERS[2].0);
    let raw = binding(&[("extension", "command.dns", "disabled")], false);
    assert_eq!(
        CompiledNativeCommandControls::for_program(&raw, Arc::new(program)).unwrap_err(),
        "native_command_control_target_unknown"
    );
}
