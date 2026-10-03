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
    assert!(allowed.explicitly_benign);
    for command in [
        "pwd; git push origin main",
        "echo ready && git push origin main",
        "git push origin main || echo failed",
        "git push origin main | head -1",
        "pwd; git push origin main; echo done",
        "gh pr view 1 --json title; git push origin main",
    ] {
        assert_eq!(
            evaluate(&controls, command).minimum_action,
            "allow",
            "{command}"
        );
    }
    for command in [
        "git push origin main; python3 project.py",
        "git push origin main; git commit -m changed",
        "git push origin main; rm -rf /",
        "git push origin main; cat .env",
        "git push origin main; echo $(whoami)",
        "git push origin main || cat .env",
        "git push origin main | python3 project.py",
        "cd /tmp; git push origin main; cat relative.txt",
        "git push origin main; echo done > .env",
        "git push origin main | head -1 ordinary.txt",
        "git push origin main | head -1 -- ordinary.txt",
    ] {
        assert_ne!(
            evaluate(&controls, command).minimum_action,
            "allow",
            "{command}"
        );
    }
    for command in [
        "cat ordinary.txt; git push origin main",
        "cat alias.txt; git push origin main",
        "ls ordinary.txt; git push origin main",
        "ls; git push origin main",
        "stat ordinary.txt; git push origin main",
    ] {
        assert_ne!(
            evaluate(&controls, command).minimum_action,
            "allow",
            "context-free wrappers cannot prove file targets: {command}"
        );
    }
    #[cfg(unix)]
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/compound-context")
            .join(format!(
                "fixture-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("ordinary.txt"), "fixture").unwrap();
        std::fs::write(root.join(".env"), "SYNTHETIC_ONLY=fixture").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let alias = root.join("alias.txt");
        std::os::unix::fs::symlink(root.join(".env"), &alias).unwrap();
        for (path, expected) in [("ordinary.txt", true), ("alias.txt", false)] {
            let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
                "omp",
                "PreToolUse",
                &serde_json::json!({"tool_name":"bash", "tool_input":{
                    "command":format!("cat {path}; git push origin main")
                }}),
                Some(&controls),
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(result.minimum_action == "allow", expected, "{path}");
        }
        let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name":"bash", "tool_input":{
                "command":"git push origin main; cat ordinary.txt"
            }}),
            Some(&controls),
            None,
            root.to_str(),
            root.to_str(),
        );
        assert_ne!(
            result.minimum_action, "allow",
            "earlier approved execution may change a file target"
        );
        for (command, expected) in [
            ("ls -la; git push origin main", false),
            ("ls -la ordinary.txt; git push origin main", true),
        ] {
            let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
                "omp",
                "PreToolUse",
                &serde_json::json!({"tool_name":"bash", "tool_input":{"command":command}}),
                Some(&controls),
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(result.minimum_action == "allow", expected, "{command}");
        }
        for (path, expected) in [("ordinary.txt", true), ("alias.txt", false)] {
            let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
                "omp",
                "PreToolUse",
                &serde_json::json!({"tool_name":"bash", "tool_input":{
                    "command":format!("stat {path}; git push origin main")
                }}),
                Some(&controls),
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(result.minimum_action == "allow", expected, "stat {path}");
        }
        let home_only = crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name":"bash", "tool_input":{
                "command":"cat alias.txt; git push origin main"
            }}),
            Some(&controls),
            None,
            root.to_str(),
            None,
        );
        assert_ne!(
            home_only.minimum_action, "allow",
            "home-only context cannot prove relative symlink targets"
        );
        for cwd in [".", ""] {
            let relative_context = crate::pretool::evaluate_pre_tool_envelope_with_context(
                "omp",
                "PreToolUse",
                &serde_json::json!({"tool_name":"bash", "tool_input":{
                    "command":"cat alias.txt; git push origin main"
                }}),
                Some(&controls),
                None,
                root.to_str(),
                Some(cwd),
            );
            assert_ne!(
                relative_context.minimum_action, "allow",
                "relative or empty cwd cannot prove path targets: {cwd:?}"
            );
        }
        let missing_cwd = root.join("missing-context-root");
        let unresolved_context = crate::pretool::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name":"bash", "tool_input":{
                "command":"cat alias.txt; git push origin main"
            }}),
            Some(&controls),
            None,
            root.to_str(),
            missing_cwd.to_str(),
        );
        assert_ne!(
            unresolved_context.minimum_action, "allow",
            "unresolvable cwd cannot prove path targets"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    let mut mixed = binding.clone();
    mixed.layers[0].controls.push(
        serde_json::from_value(serde_json::json!({
            "target_kind": "permission",
            "target_id": "command.github.permission.read-remote",
            "state": "disabled"
        }))
        .unwrap(),
    );
    mixed.effective_digest = mixed.compute_effective_digest().unwrap();
    let mixed_controls = CompiledNativeCommandControls::new(&mixed).unwrap();
    for operator in [";", "&&", "||", "|"] {
        for command in [
            format!("git push origin main {operator} gh pr view 1 --json title"),
            format!("gh pr view 1 --json title {operator} git push origin main"),
        ] {
            assert_eq!(
                evaluate(&mixed_controls, &command).minimum_action,
                "block",
                "a denied segment must dominate regardless of position: {command}"
            );
        }
    }
    let mut disabled = binding.clone();
    disabled.layers[0].controls[0].state = "disabled".into();
    disabled.effective_digest = disabled.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&disabled).unwrap();
    assert_eq!(
        evaluate(&controls, "git push origin main").minimum_action,
        "block"
    );
    for operator in [";", "&&", "||", "|"] {
        for command in [
            format!("gh pr view 1 --json title {operator} git push origin main"),
            format!("git push origin main {operator} gh pr view 1 --json title"),
        ] {
            assert_eq!(
                evaluate(&controls, &command).minimum_action,
                "block",
                "a benign GitHub segment must not hide denied Git: {command}"
            );
        }
    }

    let mut delegated = binding.clone();
    delegated.layers[0].controls[0].target_id = "command.git.permission.status".into();
    delegated.layers[0].controls[0].state = "disabled".into();
    delegated.effective_digest = delegated.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&delegated).unwrap();
    for command in [
        "git -C project status --short",
        "pwd; git -Cproject status --short; echo done",
    ] {
        assert_eq!(
            evaluate(&controls, command).minimum_action,
            "block",
            "{command}"
        );
    }

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
    assert_eq!(
        evaluate(&controls, "pwd; git push origin main; echo done").minimum_action,
        "block"
    );
}
