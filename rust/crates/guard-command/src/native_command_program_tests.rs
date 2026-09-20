use super::*;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::pretool::evaluate_pre_tool_envelope_with_extensions;
use guard_contracts::{
    NativeCommandControlBindingV1, NativeExtensionControlLayerV1, NativeExtensionControlV1,
    NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
};

fn model(command: &str) -> CanonicalCommandV1 {
    crate::parse_command(&serde_json::from_value(serde_json::json!({"command": command})).unwrap())
        .unwrap()
}

fn binding(controls: &[(&str, &str, &str)], managed: bool) -> NativeCommandControlBindingV1 {
    let program = packaged_command_program().unwrap();
    let mut binding = NativeCommandControlBindingV1 {
        schema: NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.into(),
        authority: None,
        program_digest: program.program_digest.clone(),
        catalog_digest: program.catalog_digest.clone(),
        trust_digest: program.trust_digest.clone(),
        health: "protected".into(),
        revision: 1,
        managed_revision: 2,
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
                .map(|(kind, id, state)| NativeExtensionControlV1 {
                    target_kind: (*kind).into(),
                    target_id: (*id).into(),
                    state: (*state).into(),
                })
                .collect(),
        }],
    };
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    binding
}

fn decision(
    command: &str,
    binding: &NativeCommandControlBindingV1,
) -> guard_contracts::PreToolResultV1 {
    let controls = CompiledNativeCommandControls::new(binding).unwrap();
    evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "Bash", "tool_input": { "command": command }
        }),
        Some(&controls),
        None,
    )
}

#[test]
fn packaged_program_is_admitted_once_and_exposes_explicit_coverage() {
    let first = packaged_command_program().unwrap();
    assert!(Arc::ptr_eq(&first, &packaged_command_program().unwrap()));
    assert_eq!(first.extensions.len(), 71);
    assert_eq!(first.rules.len(), 234);
    assert_eq!(
        first
            .rules
            .iter()
            .filter(|rule| rule.matcher.is_none())
            .count(),
        42
    );
    assert!(first
        .runtime_coverage()
        .iter()
        .any(|(id, supported)| *id == "command.ollama.push" && *supported));
}

#[test]
fn complete_observations_match_independent_python_reference_models() {
    let program = packaged_command_program().unwrap();
    let active = program
        .extensions
        .iter()
        .map(|extension| extension.extension_id.clone())
        .collect();
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/native-command-observations-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["semantic_profile"], "cpython-3.12-ucd15");
    let mut mismatches = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let command: CanonicalCommandV1 = serde_json::from_value(case["model"].clone()).unwrap();
        let actual = program
            .observe_declarative(&command, &active, None)
            .unwrap();
        // This fixture independently covers Python declarative observations.
        // Compatibility attribution has a separate, explicit qualification set.
        let declarative: Vec<_> = actual
            .observations
            .iter()
            .filter(|observation| {
                program
                    .rules
                    .iter()
                    .any(|rule| rule.rule_id == observation.rule_id && rule.matcher.is_some())
            })
            .collect();
        let value = serde_json::to_value(declarative).unwrap();
        if value != case["observations"] {
            mismatches.push(format!(
                "{}\nexpected={}\nactual={}",
                case["command"], case["observations"], value
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} differences; first:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn local_opt_in_selects_ollama_and_safe_evidence_stays_on_its_own_segment() {
    let enabled = binding(&[("extension", "command.ollama", "enabled")], false);
    let plain = decision("ollama push model", &enabled);
    assert!(matches!(plain.minimum_action.as_str(), "review" | "block"));
    let evidence = plain.command_extensions.unwrap();
    let push = evidence
        .observations
        .iter()
        .find(|item| item.rule_id == "command.ollama.push")
        .unwrap();
    assert_eq!(push.effective_segment_indexes, [0]);
    assert!(push.uncertainty_reasons.is_empty());
    let mixed = decision("ollama push first --help && ollama rm second", &enabled)
        .command_extensions
        .unwrap();
    assert!(mixed
        .observations
        .iter()
        .find(|item| item.rule_id == "command.ollama.push")
        .unwrap()
        .effective_segment_indexes
        .is_empty());
    assert_eq!(
        mixed
            .observations
            .iter()
            .find(|item| item.rule_id == "command.ollama.rm")
            .unwrap()
            .effective_segment_indexes,
        [1]
    );
    for inactive in [
        binding(&[], false),
        binding(&[("extension", "command.ollama", "enabled")], true),
        binding(&[("extension", "command.ollama", "disabled")], false),
    ] {
        assert!(decision("ollama push model", &inactive)
            .command_extensions
            .unwrap()
            .observations
            .iter()
            .all(|item| item.extension_id != "command.ollama"));
    }
}

#[test]
fn disabled_permission_and_failed_authority_cannot_become_allow() {
    let disabled = binding(
        &[
            ("extension", "command.ollama", "enabled"),
            ("permission", "command.ollama.permission.push", "disabled"),
        ],
        false,
    );
    assert_eq!(
        decision("ollama push model", &disabled).minimum_action,
        "block"
    );
    let mut unavailable = binding(&[], false);
    unavailable.health = "tampered".into();
    unavailable.effective_digest = unavailable.compute_effective_digest().unwrap();
    assert_eq!(decision("pwd", &unavailable).minimum_action, "block");
    let enabled = binding(
        &[(
            "permission",
            "command.filesystem.permission.recursive-remove",
            "enabled",
        )],
        false,
    );
    // Unknown targets are rejected during admission, never silently ignored.
    assert!(CompiledNativeCommandControls::new(&enabled).is_err());
}

#[test]
fn a_previously_reviewable_command_becomes_a_hard_floor_after_permission_disable() {
    let enabled = binding(&[("extension", "command.ollama", "enabled")], false);
    let before = decision("ollama push model", &enabled);
    assert_eq!(before.minimum_action, "review");
    let mut disabled = binding(
        &[
            ("extension", "command.ollama", "enabled"),
            ("permission", "command.ollama.permission.push", "disabled"),
        ],
        false,
    );
    disabled.revision = enabled.revision + 1;
    disabled.effective_digest = disabled.compute_effective_digest().unwrap();
    let after = decision("ollama push model", &disabled);
    assert_eq!(after.minimum_action, "block");
    assert_eq!(after.policy_action, "block");
    assert_eq!(after.decision, "deny");
    let old = before.command_extensions.unwrap().binding;
    let current = after.command_extensions.unwrap().binding;
    assert_ne!(
        old.control_effective_digest,
        current.control_effective_digest
    );
    assert_eq!(current.control_revision, old.control_revision + 1);
    // The production worker only calls ordinary review approval reuse for a
    // review floor. Its persisted-row integration is qualified separately.
}

#[test]
fn controls_are_bound_to_program_and_both_independent_revisions() {
    let original = binding(&[("extension", "command.ollama", "enabled")], false);
    let first = decision("ollama push model", &original)
        .command_extensions
        .unwrap();
    let mut changed = original.clone();
    changed.managed_revision += 1;
    changed.effective_digest = changed.compute_effective_digest().unwrap();
    let second = decision("ollama push model", &changed)
        .command_extensions
        .unwrap();
    assert_ne!(
        first.binding.control_effective_digest,
        second.binding.control_effective_digest
    );
    assert_ne!(
        first.binding.managed_control_revision,
        second.binding.managed_control_revision
    );
    assert_eq!(
        first.binding.observations_digest,
        second.binding.observations_digest
    );
    changed.program_digest = "f".repeat(64);
    assert!(CompiledNativeCommandControls::new(&changed).is_err());
    let controls = CompiledNativeCommandControls::new(&original).unwrap();
    let result = controls.apply(
        &model("ollama push model"),
        decision("pwd", &original),
        Some(Instant::now()),
    );
    assert_eq!(result.minimum_action, "block");
    let observations = result.command_extensions.unwrap();
    assert_eq!(
        observations.evaluation_error.as_deref(),
        Some("native_command_evaluation_failed")
    );
    assert_eq!(observations.binding.uncertainty_count, 1);
}

#[test]
fn admission_rejects_tampered_unknown_and_invalid_nodes() {
    let mut value: Value = serde_json::from_slice(EMBEDDED_PROGRAM).unwrap();
    value["semantic_profile"] = "unqualified-unicode".into();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        NativeCommandProgram::from_packaged_bytes(&bytes).unwrap_err(),
        "native_command_program_digest_mismatch"
    );
    value.as_object_mut().unwrap().remove("program_digest");
    value["program_digest"] = digest_value(PROGRAM_DOMAIN, &value).unwrap().into();
    assert_eq!(
        NativeCommandProgram::from_packaged_bytes(&serde_json::to_vec(&value).unwrap())
            .unwrap_err(),
        "native_command_program_version_unsupported"
    );
    let unknown = RawNode {
        op: "arbitrary-python-import.v1".into(),
        config: serde_json::json!({}),
        children: BTreeMap::new(),
    };
    assert_eq!(
        compile_node(unknown, &BTreeMap::new()).unwrap_err(),
        "native_command_operation_unknown"
    );
}

#[test]
fn graph_depth_proof_cannot_be_bypassed_by_memoized_shared_children() {
    let mut nodes = vec![Node {
        operation: "arguments.v1".into(),
        matcher: Matcher::Arguments(ArgumentsNode {
            executables: BTreeSet::new(),
            required_arguments: BTreeSet::new(),
        }),
    }];
    for index in 1..=MAX_DEPTH + 1 {
        nodes.push(Node {
            operation: "any.v1".into(),
            matcher: Matcher::Any(vec![index - 1]),
        });
    }
    let mut visit = vec![0; nodes.len()];
    let mut heights = vec![0; nodes.len()];
    for index in 0..=MAX_DEPTH {
        assert_eq!(
            validate_graph(index, &nodes, &mut visit, &mut heights, 0).unwrap(),
            index
        );
    }
    assert!(validate_graph(MAX_DEPTH + 1, &nodes, &mut visit, &mut heights, 0).is_err());
}

#[test]
fn compatibility_safe_commands_and_ruleless_permissions_obey_controls() {
    let unrestricted = binding(&[], false);
    assert_eq!(
        decision("git status", &unrestricted).minimum_action,
        "allow"
    );
    for (kind, target, command) in [
        ("extension", "command.git", "git status"),
        ("permission", "command.git.permission.status", "git status"),
        ("permission", "command.git.permission.diff", "git diff"),
        ("extension", "command.github", "gh pr list"),
        (
            "permission",
            "command.github.permission.read-remote",
            "gh pr list",
        ),
        (
            "permission",
            "command.github.permission.read-local",
            "gh auth status",
        ),
        (
            "permission",
            "command.github.permission.propose-remote",
            "gh pr create --title title --body body",
        ),
    ] {
        let controlled = binding(&[(kind, target, "disabled")], false);
        assert_eq!(
            decision(command, &controlled).minimum_action,
            "block",
            "{command} {target}"
        );
    }
    let direct = decision("gh pr list", &unrestricted)
        .command_extensions
        .unwrap();
    assert!(direct
        .permission_observations
        .iter()
        .any(|item| item.permission_id == "command.github.permission.read-remote"));
    for command in [
        "gh api graphql -f query='{ viewer { login } }'",
        "git rev-parse --git-dir",
        "docker compose ps",
    ] {
        let result = decision(command, &unrestricted);
        assert_eq!(result.minimum_action, "block", "{command}");
        assert!(result.command_extensions.unwrap().binding.uncertainty_count > 0);
    }
}

#[test]
fn never_enrolled_defaults_keep_first_party_protection_without_external_activation() {
    let mut fresh = binding(&[], false);
    fresh.health = "unenrolled".into();
    fresh.revision = 0;
    fresh.managed_revision = 0;
    fresh.layers.clear();
    fresh.authority = Some(guard_contracts::NativeCommandControlAuthorityV1 {
        epoch: 1,
        mutation_revision: 1,
        authority_key_id: "0".repeat(64),
        recovery: None,
    });
    fresh.effective_digest = fresh.compute_effective_digest().unwrap();
    assert_eq!(decision("pwd", &fresh).minimum_action, "allow");
    assert_eq!(decision("rm -rf /", &fresh).minimum_action, "block");
    let external = decision("ollama rm model", &fresh);
    assert_eq!(external.minimum_action, "review");
    assert!(!external
        .command_extensions
        .unwrap()
        .observations
        .iter()
        .any(|item| item.extension_id == "command.ollama"));
    for fault in 0..4 {
        let mut invalid = fresh.clone();
        match fault {
            0 => invalid.revision = 1,
            1 => invalid.managed_revision = 1,
            2 => invalid.authority.as_mut().unwrap().authority_key_id = "a".repeat(64),
            _ => invalid.authority.as_mut().unwrap().epoch = 2,
        }
        invalid.effective_digest = invalid.compute_effective_digest().unwrap();
        assert_eq!(decision("pwd", &invalid).minimum_action, "block");
    }
}

#[test]
fn delegated_packages_have_owned_native_permission_controls() {
    let program = packaged_command_program().unwrap();
    let delegated: Vec<_> = program
        .extensions
        .iter()
        .filter(|extension| extension.delegated_protection.as_deref() == Some("package-firewall"))
        .collect();
    assert_eq!(delegated.len(), 8);
    for extension in delegated {
        let permission = &extension.permissions[0].permission_id;
        let controls = CompiledNativeCommandControls::new(&binding(
            &[("permission", permission, "disabled")],
            false,
        ))
        .unwrap();
        let command = format!("{} install fixture-package", extension.executables[0]);
        let result = evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name":"Bash","tool_input":{"command":command}}),
            Some(&controls),
            None,
        );
        assert_eq!(result.minimum_action, "block", "{}", extension.extension_id);
        let observations = result.command_extensions.unwrap();
        assert!(observations
            .permission_observations
            .iter()
            .any(|item| &item.permission_id == permission));
        let help = format!("{} --help", extension.executables[0]);
        let result = evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"command":help}),
            Some(&controls),
            None,
        );
        assert!(!result
            .command_extensions
            .unwrap()
            .permission_observations
            .iter()
            .any(|item| &item.permission_id == permission));
    }
}

#[test]
fn native_mcp_defaults_are_opt_in_tightening_only_and_redacted() {
    let tool = serde_json::json!({"tool_name":"mcp__filesystem__write_file", "tool_input":{"path":"fixture.txt","content":"private-fixture-content"}});
    let inactive = CompiledNativeCommandControls::new(&binding(&[], false)).unwrap();
    let off = evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &tool,
        Some(&inactive),
        None,
    );
    assert_eq!(off.minimum_action, "review");
    assert!(off
        .command_extensions
        .unwrap()
        .permission_observations
        .is_empty());
    let enabled = CompiledNativeCommandControls::new(&binding(
        &[("extension", "command.mcp-filesystem", "enabled")],
        false,
    ))
    .unwrap();
    let on = evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &tool,
        Some(&enabled),
        None,
    );
    assert_eq!(on.minimum_action, "block");
    let observations = on.command_extensions.unwrap();
    assert_eq!(
        observations.permission_observations[0].mcp_tool.as_deref(),
        Some("write_file")
    );
    assert!(observations.permission_observations[0]
        .matcher_evidence
        .is_empty());
    let encoded = serde_json::to_string(&observations).unwrap();
    assert!(!encoded.contains("private-fixture-content") && !encoded.contains("fixture.txt"));
    let read = serde_json::json!({"tool_name":"mcp__filesystem__read_file","tool_input":{"path":"fixture.txt"}});
    let inherited = evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &read,
        Some(&enabled),
        None,
    );
    assert_eq!(inherited.minimum_action, "review");
    let managed = CompiledNativeCommandControls::new(&binding(
        &[("extension", "command.mcp-filesystem", "enabled")],
        true,
    ))
    .unwrap();
    let not_opted_in = evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &tool,
        Some(&managed),
        None,
    );
    assert_eq!(not_opted_in.minimum_action, "review");
    assert!(not_opted_in
        .command_extensions
        .unwrap()
        .permission_observations
        .is_empty());

    let hosted = CompiledNativeCommandControls::new(&binding(
        &[("extension", "command.mcp-instapods", "enabled")],
        false,
    ))
    .unwrap();
    for tool_name in [
        "mcp__instapods__delete_pod",
        "mcp__instapods-mcp__exec_command",
    ] {
        let hosted_tool =
            serde_json::json!({"tool_name":tool_name,"tool_input":{"fixture":"synthetic"}});
        let reviewed = evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &hosted_tool,
            Some(&hosted),
            None,
        );
        assert_eq!(reviewed.minimum_action, "review", "{tool_name}");
        let observations = reviewed.command_extensions.unwrap();
        assert!(observations.permission_observations.iter().any(|item| {
            item.extension_id == "command.mcp-instapods"
                && item.permission_id == "command.mcp-instapods.permission.mcp-instapods-tool"
        }));
    }
}
