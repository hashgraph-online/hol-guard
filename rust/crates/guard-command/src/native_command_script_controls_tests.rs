use super::*;

fn baseline() -> NativeCommandControlBindingV1 {
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
    binding
}

fn evaluate(command: &str, binding: &NativeCommandControlBindingV1) -> PreToolResultV1 {
    let controls = CompiledNativeCommandControls::new(binding).unwrap();
    crate::pretool::evaluate_pre_tool_envelope_with_extensions(
        "zcode",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
    )
}

#[test]
fn file_shell_invocations_retain_review_without_evaluation_failure() {
    let binding = baseline();
    for command in [
        "bash ./preflight.sh fixture",
        "sh -- './pre flight.sh' fixture",
        "zsh ./fixtures/preflight.sh",
    ] {
        let result = evaluate(command, &binding);
        assert_eq!(
            result.minimum_action, "review",
            "{command}: {}",
            result.reason_code
        );
        assert_eq!(
            result.decision, "deny",
            "unreviewed scripts must not execute"
        );
        assert!(!result.explicitly_benign);
        assert!(result
            .command_extensions
            .as_ref()
            .unwrap()
            .evaluation_error
            .is_none());
    }
}

#[test]
fn file_shell_invocations_cannot_hide_critical_siblings_or_invalid_authority() {
    let binding = baseline();
    let result = evaluate("bash ./preflight.sh && shutdown -h now", &binding);
    assert_eq!(result.minimum_action, "block");
    for health in ["tampered", "recovery-required"] {
        let mut blocked = binding.clone();
        blocked.health = health.into();
        blocked.effective_digest = blocked.compute_effective_digest().unwrap();
        assert_eq!(
            evaluate("bash ./preflight.sh", &blocked).minimum_action,
            "block",
            "{health}"
        );
    }
}
