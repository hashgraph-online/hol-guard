use super::*;

#[test]
fn codex_browser_process_timing_is_not_a_credential_selector() {
    for token in [
        "linux:12345",
        "windows:134036121234567890",
        "posix:Thu Oct  1 01:02:03 2026",
    ] {
        let payload = json!({"tool_name": "Bash", "tool_input": {"command": "pwd"},
            "guard_codex_browser_wait_process": {"pid": 123, "startToken": token}});
        let mut installed = policy("allow");
        installed
            .risk_actions
            .insert("local_secret_read".into(), "block".into());
        let native =
            guard_command::pretool::evaluate_pre_tool_envelope("codex", "PreToolUse", &payload);
        let result = apply_pre_tool_policy(&snapshot(installed), &payload, native).unwrap();
        assert_eq!(result.decision, "allow", "{}", result.reason_code);
    }
}

#[test]
fn codex_browser_process_metadata_does_not_hide_credentials() {
    for payload in [
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd", "startToken": "linux:123"}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd"},
            "guard_codex_browser_wait_process": {"pid": 123, "startToken": "private credential"}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd"},
            "guard_codex_browser_wait_process": {"pid": 0, "startToken": "linux:123"}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd"},
            "guard_codex_browser_wait_process": {"pid": 123, "startToken": "linux:123", "secret": "private"}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd"},
            "nested": {"guard_codex_browser_wait_process": {"pid": 123, "startToken": "linux:123"}}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "cat credentials.yaml"},
            "guard_codex_browser_wait_process": {"pid": 123, "startToken": "linux:123"}}),
    ] {
        let mut installed = policy("allow");
        installed
            .risk_actions
            .insert("local_secret_read".into(), "block".into());
        let native =
            guard_command::pretool::evaluate_pre_tool_envelope("codex", "PreToolUse", &payload);
        let result = apply_pre_tool_policy(&snapshot(installed), &payload, native).unwrap();
        assert_eq!(result.decision, "deny");
    }
}

#[test]
fn codex_browser_process_metadata_exception_does_not_apply_to_other_harnesses() {
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "pwd"},
        "guard_codex_browser_wait_process": {"pid": 123, "startToken": "linux:123"}});
    let mut installed = policy("allow");
    installed
        .risk_actions
        .insert("local_secret_read".into(), "block".into());
    let native =
        guard_command::pretool::evaluate_pre_tool_envelope("claude-code", "PreToolUse", &payload);
    let result = apply_pre_tool_policy(&snapshot(installed), &payload, native).unwrap();
    assert_eq!(result.decision, "deny");
}

#[test]
fn codex_command_output_budget_is_not_a_credential_read() {
    let mut installed_policy = policy("allow");
    installed_policy
        .risk_actions
        .insert("local_secret_read".into(), "require-reapproval".into());
    for tool in ["exec_command", "functions.exec_command"] {
        for budget in [0, 2000] {
            let payload = json!({
                "tool_name": tool,
                "tool_input": {"cmd": "pwd", "max_output_tokens": budget}
            });
            let native_result =
                guard_command::pretool::evaluate_pre_tool_envelope("codex", "PreToolUse", &payload);
            assert_eq!(
                native_result.action.action_type,
                PreToolActionTypeV1::Command
            );
            assert!(!native_result.action.sensitive_target);
            let output =
                apply_pre_tool_policy(&snapshot(installed_policy.clone()), &payload, native_result)
                    .expect("ordinary bounded command input");
            assert_eq!(output.decision, "allow", "{}", output.reason_code);
            assert_eq!(output.minimum_action, "allow");
        }
    }
}

#[test]
fn codex_budget_metadata_preserves_credential_named_read_review() {
    for tool in ["exec_command", "functions.exec_command"] {
        for command in [
            "cat credentials.yaml",
            "head token.txt",
            "cat ./config/access-token.json",
            "rg -n key credentials.yaml",
            "grep -n key token.txt",
            "git show --no-ext-diff --no-textconv HEAD:credentials.yaml",
            "git show --no-ext-diff --no-textconv HEAD:*.yaml",
            "git diff --no-ext-diff --no-textconv -- '*.json'",
            "git show --no-ext-diff --no-textconv HEAD -- ':(top)credentials.yaml'",
            "git diff --no-ext-diff --no-textconv -- ':(literal)credentials.yaml'",
            "cat credentials/cache.dat",
            "cat auth.json",
            "cat authorization.yaml",
            "cat passwd.txt",
            "cat id_dsa",
            "rg -n key -g 'creden[t]ials.yaml' .",
            "rg -n key -g 'access-?o?e?.json' .",
        ] {
            let payload = json!({"tool_name": tool, "tool_input": {
                "cmd": command, "max_output_tokens": 2000
            }});
            let native_result =
                guard_command::pretool::evaluate_pre_tool_envelope("codex", "PreToolUse", &payload);
            let output = apply_pre_tool_policy(&snapshot(policy("allow")), &payload, native_result)
                .expect("credential-named read fixture");
            assert_eq!(output.decision, "deny", "{tool}: {command}");
            assert_ne!(output.minimum_action, "allow");
        }
    }
}

#[test]
fn codex_budget_metadata_keeps_ordinary_relative_reads_exact_safe() {
    for command in [
        "cat README.md",
        "cat tokenizer.rs",
        "cat auth.ts",
        "cat src/auth/handlers.ts",
        "rg -g*.ts authority src",
    ] {
        let payload = json!({"tool_name": "exec_command", "tool_input": {
            "cmd": command, "max_output_tokens": 2000
        }});
        let native_result =
            guard_command::pretool::evaluate_pre_tool_envelope("codex", "PreToolUse", &payload);
        let output = apply_pre_tool_policy(&snapshot(policy("allow")), &payload, native_result)
            .expect("ordinary relative read fixture");
        assert_eq!(output.decision, "allow", "{command}");
    }
}

#[test]
fn codex_budget_metadata_preserves_native_command_review() {
    let payload = json!({"tool_name": "exec_command", "tool_input": {
        "cmd": "touch allowed.marker", "max_output_tokens": 2000
    }});
    let native_result =
        guard_command::pretool::evaluate_pre_tool_envelope("codex", "PreToolUse", &payload);
    assert_eq!(native_result.decision, "deny");
    let intrinsic_action = native_result.minimum_action.clone();
    let mut installed_policy = policy("allow");
    installed_policy
        .risk_actions
        .insert("local_secret_read".into(), "require-reapproval".into());
    let output = apply_pre_tool_policy(&snapshot(installed_policy), &payload, native_result)
        .expect("native command review fixture");
    assert_eq!(output.decision, "deny");
    assert_eq!(output.minimum_action, intrinsic_action);
}

#[test]
fn codex_budget_metadata_does_not_hide_sensitive_inputs() {
    let payloads = [
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": "synthetic-secret"
        }}),
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": -1
        }}),
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": true
        }}),
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": 1.5
        }}),
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": null
        }}),
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": 2000,
            "access_token": "synthetic-secret"
        }}),
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": 2000,
            "nested": {"max_output_tokens": 2000}
        }}),
        json!({"tool_name": "exec_command", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": 2000,
            "file_path": ".ssh/id_rsa"
        }}),
        json!({"tool_name": "unrecognized_tool", "tool_input": {
            "cmd": "touch allowed.marker", "max_output_tokens": 2000
        }}),
        json!({"tool_name": "exec_command", "max_output_tokens": 2000,
            "tool_input": {"cmd": "touch allowed.marker"}}),
    ];
    for payload in payloads {
        let mut installed_policy = policy("allow");
        installed_policy
            .risk_actions
            .insert("local_secret_read".into(), "require-reapproval".into());
        let mut native_result = generic_result("allow");
        native_result.action.harness = "codex".into();
        let output = apply_pre_tool_policy(&snapshot(installed_policy), &payload, native_result)
            .expect("bounded sensitive fixture");
        assert_eq!(output.decision, "deny", "{payload}");
        assert_eq!(output.minimum_action, "require-reapproval", "{payload}");
    }
}

#[test]
fn codex_budget_exception_preserves_other_harnesses_and_deny_floors() {
    let payload = json!({"tool_name": "exec_command", "tool_input": {
        "cmd": "touch allowed.marker", "max_output_tokens": 2000
    }});
    let mut installed_policy = policy("allow");
    installed_policy
        .risk_actions
        .insert("local_secret_read".into(), "require-reapproval".into());
    let output = apply_pre_tool_policy(
        &snapshot(installed_policy),
        &payload,
        generic_result("allow"),
    )
    .expect("other harness fixture");
    assert_eq!(output.minimum_action, "require-reapproval");

    for (default_action, intrinsic_action) in [("block", "allow"), ("allow", "block")] {
        let mut native_result = generic_result(intrinsic_action);
        native_result.action.harness = "codex".into();
        let output =
            apply_pre_tool_policy(&snapshot(policy(default_action)), &payload, native_result)
                .expect("deny floor fixture");
        assert_eq!(output.decision, "deny");
        assert_eq!(output.minimum_action, "block");
    }
}

#[test]
fn codex_post_budget_preserves_sensitive_output_policy_facts() {
    // This covers policy facts after scanning, not the native output scanner.
    let mut effective = policy("allow");
    effective
        .risk_actions
        .insert("local_secret_read".into(), "require-reapproval".into());
    let installed = snapshot(effective);
    for tool in ["exec_command", "functions.exec_command"] {
        for credential_output in [false, true] {
            let output = if credential_output {
                json!({"access_token": "synthetic-secret"})
            } else {
                json!({"output": "ordinary output"})
            };
            let mut request = post_request(json!({
                "tool_name": tool,
                "tool_input": {"cmd": "pwd", "max_output_tokens": 2000},
                "tool_response": output
            }));
            request.harness = "codex".into();
            let result = apply_post_tool_policy(
                &installed,
                &request,
                GuardHookPayloadKindV2::Inline,
                HookReviewResponseV1::allow("output_scan_allow"),
            )
            .expect("bounded Codex output fixture");
            assert_eq!(
                result.decision,
                if credential_output { "deny" } else { "allow" }
            );
            assert_eq!(
                result.policy_action.as_deref(),
                Some(if credential_output {
                    "require-reapproval"
                } else {
                    "allow"
                })
            );
        }
    }
}

#[test]
fn codex_routine_apply_patch_clears_the_persistence_floor() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("guard-runtime-apply-patch-{}", std::process::id()));
    let workspace = root.join("home/project");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/settings.ts"), "retryLimit: 3,\n").unwrap();
    std::fs::write(workspace.join(".env"), "TOKEN=synthetic\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let (home, workspace) = (root.join("home"), root.join("home/project"));
    let mut installed = policy("allow");
    installed
        .risk_actions
        .insert("persistence".into(), "require-reapproval".into());
    let review = |target: &str| {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": format!(
                "*** Begin Patch\n*** Update File: {target}\n@@\n-  retryLimit: 3,\n+  retryLimit: 5,\n*** End Patch"
            )}
        });
        let native = guard_command::pretool::evaluate_pre_tool_envelope_with_context(
            "codex",
            "PreToolUse",
            &payload,
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        );
        apply_pre_tool_policy(&snapshot(installed.clone()), &payload, native).unwrap()
    };
    let routine = review(&workspace.join("src/settings.ts").display().to_string());
    assert_eq!(routine.decision, "allow", "{}", routine.reason_code);
    assert_eq!(review(".env").decision, "deny");
}
