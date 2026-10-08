use super::*;

fn binding_with_layers(layers: serde_json::Value) -> NativeCommandControlBindingV1 {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": layers
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    binding
}

fn disabled_permission_layer(rule_id: &str) -> serde_json::Value {
    let program = packaged_command_program().unwrap();
    let permission = program
        .rules
        .iter()
        .find(|rule| rule.rule_id == rule_id)
        .unwrap()
        .permission_id
        .clone();
    serde_json::json!([{
        "schema_version": "1.0.0", "kind": "local-admin", "catalog_digest": program.catalog_digest,
        "global_lockdown": false, "controls": [{
            "target_kind": "permission", "target_id": permission, "state": "disabled"
        }]
    }])
}

fn evaluate(binding: &NativeCommandControlBindingV1, command: &str) -> PreToolResultV1 {
    let controls = CompiledNativeCommandControls::new(binding).unwrap();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &serde_json::json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(&controls),
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    )
}

#[test]
fn uncertain_git_attribution_requires_review_instead_of_a_hard_block() {
    let binding = binding_with_layers(serde_json::json!([]));
    for command in [
        "git cat-file -p HEAD",
        "git notes list",
        "git fetch origin main",
    ] {
        let result = evaluate(&binding, command);
        assert_eq!(result.minimum_action, "review", "{command}");
        assert!(!result.explicitly_benign, "{command}");
        let evidence = result.command_extensions.as_ref().unwrap();
        assert!(evidence.binding.uncertainty_count > 0, "{command}");
    }
}

#[test]
fn a_disabled_permission_still_blocks_uncertain_and_redirected_commands() {
    let binding = binding_with_layers(disabled_permission_layer("command.git.push"));
    for command in [
        "git cat-file -p HEAD",
        "git notes list",
        "git push origin main > /tmp/push.log",
    ] {
        let result = evaluate(&binding, command);
        assert_eq!(result.minimum_action, "block", "{command}");
        assert_eq!(
            result.reason_code, "native_command_permission_disabled",
            "{command}"
        );
    }
}

#[test]
fn a_disabled_git_read_permission_blocks_read_only_plumbing() {
    let binding = binding_with_layers(disabled_permission_layer("command.git.ls-files"));
    for command in ["git rev-parse HEAD", "git config --list --show-origin"] {
        let result = evaluate(&binding, command);
        assert_eq!(result.minimum_action, "block", "{command}");
        assert_eq!(
            result.reason_code, "native_command_permission_disabled",
            "{command}"
        );
    }
}

#[test]
fn global_lockdown_still_blocks_unparsed_commands() {
    let program = packaged_command_program().unwrap();
    let binding = binding_with_layers(serde_json::json!([{
        "schema_version": "1.0.0", "kind": "local-admin", "catalog_digest": program.catalog_digest,
        "global_lockdown": true, "controls": []
    }]));
    let result = evaluate(&binding, "echo hi > notes.txt");
    assert_eq!(result.minimum_action, "block");
}

#[test]
fn an_expired_deadline_still_fails_closed_for_unparsed_commands() {
    let binding = binding_with_layers(serde_json::json!([]));
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let decision = crate::pretool::evaluate_pre_tool(&crate::CommandModelRequestV1 {
        command: "echo hi > notes.txt".to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    let intrinsic = crate::pretool::evaluate_pre_tool_envelope(
        "zcode",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "echo hi > notes.txt"}}),
    );
    let result = controls.apply(
        &decision.command_model,
        intrinsic,
        Some(Instant::now() - std::time::Duration::from_secs(1)),
    );
    assert_eq!(result.minimum_action, "block");
    assert_eq!(
        result.reason_code,
        "native_command_extension_evaluation_failed"
    );
}
