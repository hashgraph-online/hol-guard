use super::*;

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
