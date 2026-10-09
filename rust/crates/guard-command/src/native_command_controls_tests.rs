use super::*;

#[test]
fn test_containment_requirement_cannot_override_lockdown() {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    let evaluate = |binding: &NativeCommandControlBindingV1, command: &str| {
        let controls = CompiledNativeCommandControls::new(binding).unwrap();
        crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name":"bash","tool_input":{"command":command}}),
            Some(&controls),
            None,
            Some("/home/tester"),
            Some("/home/tester/project"),
        )
    };
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    assert_eq!(
        evaluate(&binding, "python3 -m pytest -q").minimum_action,
        if cfg!(target_os = "macos") {
            "sandbox-required"
        } else {
            "review"
        }
    );
    binding.layers = serde_json::from_value(serde_json::json!([{
        "schema_version": "1.0.0", "kind": "local-admin", "catalog_digest": program.catalog_digest,
        "global_lockdown": true, "controls": []
    }]))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    for command in [
        "python3 -m pytest -q",
        "python3 -c 'import json; print(1)'",
        "node -e 'console.log(1)'",
    ] {
        let result = evaluate(&binding, command);
        assert_eq!(result.minimum_action, "block", "{command}");
        assert!(
            !result
                .reason_code
                .ends_with("readonly_containment_required"),
            "{command}"
        );
        assert!(!result.reason.contains("recover-authority"), "{command}");
    }
    // An administrator lockdown is not repaired by local recovery.
    binding.health = "tampered".into();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let result = evaluate(&binding, "python3 -m pytest -q");
    assert_eq!(result.minimum_action, "block");
    assert!(
        !result.reason.contains("recover-authority"),
        "{}",
        result.reason
    );
}

#[test]
fn git_containment_preserves_disabled_execution_permission() {
    let program = packaged_command_program().unwrap();
    let permission = program
        .rules
        .iter()
        .find(|rule| rule.rule_id == "command.git.diff")
        .unwrap()
        .permission_id
        .clone();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": [{
            "schema_version": "1.0.0", "kind": "local-admin", "catalog_digest": program.catalog_digest,
            "global_lockdown": false, "controls": [{
                "target_kind": "permission", "target_id": permission, "state": "disabled"
            }]
        }]
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({"tool_name":"bash", "tool_input":{"command":"git diff --stat"}}),
        Some(&controls),
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    );
    assert_eq!(result.minimum_action, "block");
    assert_ne!(
        result.reason_code,
        "native_git_readonly_containment_required"
    );
}

#[test]
fn git_context_proof_reaches_native_extension_observations() {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let repository = repository.to_str().unwrap();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "bash",
            "tool_input": {"command": "git -C rust status --short"}
        }),
        Some(&controls),
        None,
        Some(repository),
        Some(repository),
    );
    let observations = result.command_extensions.unwrap();
    assert_eq!(observations.binding.uncertainty_count, 0);
    assert!(observations.observations.iter().any(|observation| {
        observation.rule_id == "command.git.status"
            && observation.uncertainty_reasons.is_empty()
            && observation.effective_segment_indexes == [0]
    }));
}

#[test]
fn vitest_containment_never_overrides_disabled_package_permission() {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": [{
            "schema_version": "1.0.0", "kind": "local-admin", "catalog_digest": program.catalog_digest,
            "global_lockdown": false, "controls": [{
                "target_kind": "permission",
                "target_id": "command.package.node.permission.package-protection",
                "state": "disabled"
            }]
        }]
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    for command in [
        "bunx vitest run tests/example.test.ts",
        "bun run lint",
        "bunx tsc --noEmit",
        "bun run build",
        "npm test",
        "npm run test",
        "bun run test",
    ] {
        let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(&controls),
            None,
            Some("/home/tester"),
            Some("/home/tester/project"),
        );
        assert_eq!(result.minimum_action, "block", "{command}");
        assert!(
            !result
                .reason_code
                .ends_with("readonly_containment_required"),
            "{command}"
        );
    }
}

#[test]
fn timeout_wrapper_parsing_is_bounded_and_preserves_inner_commands() {
    for command in [
        "timeout 120 pwd",
        "timeout -- 120 pwd",
        "/usr/bin/timeout 120 pwd",
    ] {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.into(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "guard-shell".into(),
        })
        .unwrap();
        assert_eq!(model.confidence, "exact", "{command}");
        assert_eq!(model.wrapper_chain, ["timeout"]);
        assert_eq!(model.segments[0].executable.as_deref(), Some("pwd"));
        let result = crate::pretool::evaluate_pre_tool(&crate::CommandModelRequestV1 {
            command: command.into(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "guard-shell".into(),
        })
        .unwrap();
        assert_eq!(result.minimum_action, "review", "{command}");
    }
    for command in [
        "timeout --kill-after=1 5 pwd",
        "timeout -s KILL 5 pwd",
        "timeout 5s pwd",
        "timeout 5",
        "timeout 5 sh -c 'shutdown -h now'",
        "timeout 1 timeout 1 timeout 1 timeout 1 timeout 1 pwd",
    ] {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.into(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "guard-shell".into(),
        })
        .unwrap();
        assert_eq!(model.confidence, "uncertain", "{command}");
    }
}

#[test]
fn diagnostic_shell_commands_preserve_an_approvable_review() {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest,
        "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest,
        "health": "protected", "revision": 1, "managed_revision": 0,
        "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    for command in [
        "ss -ltn | grep ':5486'; curl -sS -m 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:5486/; hol-guard doctor 2>&1 | grep -E 'Mode|Runtime|Approval' | head -12",
        "timeout 120 ~/.local/bin/hol-guard doctor 2>&1 | tail -45",
        "timeout 120 /home/example/.local/bin/hol-guard doctor 2>&1 | tail -45",
    ] {
        let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}});
        let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "claude-code", "PreToolUse", &payload, Some(&controls),
            Some(Instant::now() + std::time::Duration::from_secs(9)),
        );
        assert_eq!(result.minimum_action, "review", "{command}: {}", result.reason_code);
        assert!(result.command_extensions.as_ref().unwrap().evaluation_error.is_none());
        assert!(!result.explicitly_benign);
    }
    let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {
        "command": "timeout 120 ~/.local/bin/hol-guard doctor 2>&1 | tail -45"
    }});
    for health in [
        "degraded-unacknowledged",
        "degraded-acknowledged",
        "tampered",
        "recovery-required",
    ] {
        let mut degraded = binding.clone();
        degraded.health = health.into();
        degraded.effective_digest = degraded.compute_effective_digest().unwrap();
        let controls = CompiledNativeCommandControls::new(&degraded).unwrap();
        let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &payload,
            Some(&controls),
            None,
        );
        assert_eq!(result.minimum_action, "block", "{health}");
        assert_eq!(
            result.reason_code, "native_command_control_authority_block",
            "{health}"
        );
        assert!(
            result
                .reason
                .contains("hol-guard command controls recover-authority"),
            "{health}: {}",
            result.reason
        );
        assert!(
            !result.reason.contains("acknowledge-degraded"),
            "{health}: {}",
            result.reason
        );
    }
    let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {
        "command": "timeout 120 git reset --hard"
    }});
    let baseline = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &payload,
        Some(&controls),
        None,
    );
    let observation = baseline
        .command_extensions
        .as_ref()
        .unwrap()
        .observations
        .iter()
        .find(|item| item.rule_id == "command.git.hard-reset")
        .unwrap();
    let rule = program
        .rules
        .iter()
        .find(|item| item.rule_id == observation.rule_id)
        .unwrap();
    for target_kind in ["extension", "permission"] {
        let target_id = if target_kind == "extension" {
            &observation.extension_id
        } else {
            &rule.permission_id
        };
        let mut blocked = binding.clone();
        blocked.layers = serde_json::from_value(serde_json::json!([{
            "schema_version": "1.0.0", "kind": "local-admin",
            "catalog_digest": program.catalog_digest, "global_lockdown": false,
            "controls": [{"target_kind": target_kind, "target_id": target_id, "state": "disabled"}]
        }]))
        .unwrap();
        blocked.effective_digest = blocked.compute_effective_digest().unwrap();
        let controls = CompiledNativeCommandControls::new(&blocked).unwrap();
        let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &payload,
            Some(&controls),
            None,
        );
        assert_eq!(result.minimum_action, "block", "disabled {target_kind}");
        assert!(result.reason_code.ends_with("disabled"));
    }
    let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {
        "command": "timeout 5 shutdown -h now"
    }});
    let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
        "claude-code",
        "PreToolUse",
        &payload,
        Some(&controls),
        None,
    );
    assert_eq!(result.minimum_action, "block", "required critical rule");
    assert!(result
        .command_extensions
        .as_ref()
        .unwrap()
        .evaluation_error
        .is_none());
}

#[test]
fn delegated_deadline_failure_is_not_an_administrator_disable() {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest,
        "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest,
        "health": "protected", "revision": 1, "managed_revision": 0,
        "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let intrinsic = crate::pretool::evaluate_pre_tool_envelope(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "mcp__filesystem__read_file", "tool_input": {"path": "fixture.txt"}}),
    );
    let result = controls.apply_with_tool(
        None,
        intrinsic,
        Some("mcp__filesystem__read_file"),
        &[],
        Some(Instant::now() - std::time::Duration::from_secs(1)),
    );
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.decision, "deny");
    let evidence = result.command_extensions.as_ref().unwrap();
    assert_eq!(
        evidence.evaluation_error.as_deref(),
        Some("native_command_evaluation_failed")
    );
    assert_eq!(evidence.binding.uncertainty_count, 1);
    assert_eq!(evidence.binding.observation_count, 0);
    assert_eq!(
        result.reason_code,
        "native_command_extension_evaluation_failed"
    );
    assert_eq!(
        result.reason,
        "HOL Guard could not evaluate the extension controls for this command. Check Guard diagnostics before retrying."
    );
}

#[test]
fn expired_extension_deadline_fail_closes_a_proven_benign_command() {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest,
        "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest,
        "health": "protected", "revision": 1, "managed_revision": 0,
        "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let intrinsic = crate::pretool::evaluate_pre_tool_envelope(
        "claude-code",
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "command": "pwd"}),
    );
    let decision = crate::pretool::evaluate_pre_tool(&crate::CommandModelRequestV1 {
        command: "pwd".to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    let result = controls.apply(
        &decision.command_model,
        intrinsic,
        Some(Instant::now() - std::time::Duration::from_secs(1)),
    );
    assert_eq!(result.minimum_action, "block");
    assert!(!result.explicitly_benign);
    assert_eq!(result.decision, "deny");
    assert_eq!(
        result.reason_code,
        "native_command_extension_evaluation_failed"
    );
    assert_eq!(
        result.reason,
        "HOL Guard could not evaluate the extension controls for this command. Check Guard diagnostics before retrying."
    );
}
