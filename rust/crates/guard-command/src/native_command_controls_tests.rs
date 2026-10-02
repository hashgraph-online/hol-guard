use super::*;

#[test]
fn explicit_command_permission_settles_only_its_covered_generic_review() {
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
    let evaluate = |controls: &CompiledNativeCommandControls, command: &str| {
        crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "omp",
            "PreToolUse",
            &serde_json::json!({
                "tool_name": "bash", "tool_input": {"command": command}
            }),
            Some(controls),
            None,
        )
    };
    let baseline = evaluate(&controls, "git push origin main");
    assert_eq!(baseline.minimum_action, "review");
    let observation = baseline
        .command_extensions
        .as_ref()
        .unwrap()
        .observations
        .iter()
        .find(|item| !item.effective_segment_indexes.is_empty())
        .unwrap();
    let permission =
        &program.rules[*controls.rule_indices.get(&observation.rule_id).unwrap()].permission_id;
    binding.layers = serde_json::from_value(serde_json::json!([{
        "schema_version": "1.0.0", "kind": "local-admin", "catalog_digest": program.catalog_digest,
        "global_lockdown": false, "controls": [
            {"target_kind": "permission", "target_id": permission, "state": "enabled"}
        ]
    }]))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let allowed = evaluate(&controls, "git push origin main");
    assert_eq!(allowed.minimum_action, "allow", "{}", allowed.reason_code);
    assert_eq!(
        allowed.reason_code,
        "native_command_explicit_permission_allow"
    );
    for command in [
        "git push origin main; python3 project.py",
        "git push origin main; rm -rf /",
        "git push origin main; cat .env",
        "git push origin main; echo $(whoami)",
    ] {
        assert_ne!(
            evaluate(&controls, command).minimum_action,
            "allow",
            "{command}"
        );
    }
    let mut disabled = binding.clone();
    disabled.layers[0].controls[0].state = "disabled".into();
    disabled.effective_digest = disabled.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&disabled).unwrap();
    assert_eq!(
        evaluate(&controls, "git push origin main").minimum_action,
        "block"
    );

    let mut delegated = binding.clone();
    delegated.layers[0].controls[0].target_id =
        "command.package.node.permission.package-protection".into();
    delegated.effective_digest = delegated.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&delegated).unwrap();
    assert_eq!(
        evaluate(&controls, "bunx vitest run tests/example.test.ts").minimum_action,
        "review",
        "enabling a protection owner is not consent to execute arbitrary package code"
    );

    binding.layers[0].global_lockdown = true;
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    assert_eq!(
        evaluate(&controls, "git push origin main").minimum_action,
        "block"
    );
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
    for health in ["degraded-unacknowledged", "tampered", "recovery-required"] {
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
