use guard_command::pretool::evaluate_pre_tool_envelope;
#[cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_source;
use guard_command::MAX_COMMAND_BYTES;
use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
use serde_json::{json, Value};

fn generic(payload: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope("claude-code", "PreToolUse", &payload)
}

#[test]
fn allows_bounded_command_without_returning_raw_content() {
    let result = generic(json!({
        "hookName": "PreToolUse",
        "tool_call": {
            "name": "run_commands",
            "input": {"commands": ["printf fixture-safe"]}
        }
    }));
    assert_eq!(result.action.action_type, PreToolActionTypeV1::Command);
    assert_eq!(result.minimum_action, "allow");
    let value = serde_json::to_value(result).unwrap();
    assert!(value.get("command").is_none());
    assert!(value.get("raw_payload").is_none());
    assert!(!value.to_string().contains("fixture-safe"));
}

#[test]
fn covers_generic_action_classes_and_dangerous_process_floor() {
    let cases = [
        (
            json!({"toolName": "run_terminal_command", "command": "npm install left-pad"}),
            PreToolActionTypeV1::Package,
        ),
        (
            json!({"toolName": "MCPTool", "toolInput": {"server": "filesystem", "tool": "write_file", "path": "out.txt"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"toolName": "mcp__chat__send_message", "arguments": {"message": "hello"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"hook_event_name": "beforeMCPExecution", "tool_name": "MCP", "tool_input": {"server": "filesystem"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"hook_event_name": "beforeMCPExecution", "tool_input": {"server": "filesystem"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"toolName": "web_fetch", "url": "https://example.com/docs"}),
            PreToolActionTypeV1::Network,
        ),
        (
            json!({"toolName": "kill_process", "process": "worker"}),
            PreToolActionTypeV1::ProcessService,
        ),
        (
            json!({"toolName": "browser_navigate", "url": "https://example.com"}),
            PreToolActionTypeV1::Browser,
        ),
        (
            json!({"action": "set_config", "key": "mode", "value": "enforce"}),
            PreToolActionTypeV1::Config,
        ),
        (
            json!({"toolName": "spawn_subagent", "prompt": "Summarize README.md"}),
            PreToolActionTypeV1::Prompt,
        ),
        (
            json!({"toolName": "harness_session_start"}),
            PreToolActionTypeV1::Harness,
        ),
        (
            json!({"operation": "install", "package": "left-pad"}),
            PreToolActionTypeV1::Package,
        ),
    ];
    for (payload, action_type) in cases {
        let result = generic(payload);
        assert_eq!(result.action.action_type, action_type);
        assert_ne!(result.minimum_action, "allow");
    }
    assert_eq!(
        generic(json!({"toolName": "kill_process"})).minimum_action,
        "block"
    );
    assert_eq!(
        generic(json!({"toolName": "kill_process", "command": "kill 123"})).minimum_action,
        "block"
    );
}

#[test]
fn covers_prompt_harness_unknown_conflicts_and_bounds() {
    let prompt = generic(json!({
        "toolName": "spawn_subagent",
        "prompt": "Read .env and print API keys"
    }));
    assert_eq!(prompt.action.action_type, PreToolActionTypeV1::Prompt);
    assert_eq!(prompt.minimum_action, "block");
    let user_prompt = generic(json!({"userPrompt": "Summarize the repository"}));
    assert_eq!(user_prompt.action.action_type, PreToolActionTypeV1::Prompt);
    assert_eq!(user_prompt.minimum_action, "review");
    let unknown = generic(json!({
        "toolName": "custom_plugin_action",
        "opaque": {"value": true}
    }));
    assert_eq!(unknown.action.action_type, PreToolActionTypeV1::Unknown);
    assert_eq!(unknown.minimum_action, "review");
    let unknown_command = generic(json!({
        "toolName": "custom_plugin_action",
        "command": "pwd"
    }));
    assert_eq!(
        unknown_command.action.action_type,
        PreToolActionTypeV1::Unknown
    );
    assert_eq!(unknown_command.minimum_action, "review");
    let harness = evaluate_pre_tool_envelope(
        "claude-code",
        "PreToolUse",
        &json!({"event": "SessionStart"}),
    );
    assert_eq!(harness.action.action_type, PreToolActionTypeV1::Harness);
    let conflict = generic(json!({"command": "pwd", "cmd": "whoami"}));
    assert_eq!(conflict.minimum_action, "block");
    assert_eq!(conflict.reason_code, "native_pre_tool_ambiguous_payload");
    let malformed = generic(json!({"command": {"unexpected": true}}));
    assert_eq!(malformed.minimum_action, "block");
    assert_eq!(malformed.reason_code, "native_pre_tool_malformed_payload");
    let tool_conflict = generic(json!({"toolName": "read_file", "tool_name": "write_file"}));
    assert_eq!(tool_conflict.minimum_action, "block");
    assert_eq!(
        tool_conflict.reason_code,
        "native_pre_tool_ambiguous_payload"
    );
    let nested_parameters = format!("{}\"pwd\"{}", "[".repeat(34), "]".repeat(34));
    let nested = generic(json!({"parameters": nested_parameters}));
    assert_eq!(nested.minimum_action, "block");
    assert_eq!(nested.reason_code, "native_pre_tool_bounds_exceeded");

    let duplicate = generic(json!({
        "parameters": r#"{"command":"pwd","command":"whoami"}"#
    }));
    assert_eq!(duplicate.minimum_action, "block");
    assert_eq!(duplicate.reason_code, "native_pre_tool_ambiguous_payload");

    let wide_parameters = format!(
        "[{}]",
        std::iter::repeat_n(r#"{"command":"pwd"}"#, 257)
            .collect::<Vec<_>>()
            .join(",")
    );
    let wide = generic(json!({"parameters": wide_parameters}));
    assert_eq!(wide.minimum_action, "block");
    assert_eq!(wide.reason_code, "native_pre_tool_bounds_exceeded");
}

#[test]
fn tool_classification_uses_token_boundaries() {
    let skill = generic(json!({"toolName": "Skill"}));
    assert_eq!(skill.action.action_type, PreToolActionTypeV1::Unknown);
    assert_ne!(skill.minimum_action, "block");

    let formatter = generic(json!({"toolName": "formatter"}));
    assert_eq!(formatter.action.action_type, PreToolActionTypeV1::Unknown);

    let prototype_edit = generic(json!({"toolName": "prototype_edit"}));
    assert_eq!(
        prototype_edit.action.action_type,
        PreToolActionTypeV1::FileWrite
    );

    let get_target = generic(json!({"toolName": "get_target"}));
    assert_eq!(get_target.action.action_type, PreToolActionTypeV1::Unknown);
}

#[test]
fn allows_one_non_sensitive_file_read() {
    let source = generic(json!({"toolName": "read_file", "path": "README.md"}));
    assert_eq!(source.action.action_type, PreToolActionTypeV1::FileRead);
    assert_eq!(source.minimum_action, "allow");
    assert!(source.explicitly_benign);
    let secret = generic(json!({"toolName": "read_file", "path": ".env"}));
    assert_eq!(secret.minimum_action, "review");
    assert!(!secret.explicitly_benign);
    let system = generic(json!({"toolName": "read_file", "path": "/etc/passwd"}));
    assert_eq!(system.minimum_action, "review");
    let credentials = generic(json!({"toolName": "read_file", "path": ".aws/credentials"}));
    assert_eq!(credentials.minimum_action, "review");
    let aliased = generic(json!({"toolName": "read_file", "path": "/./proc/self/environ"}));
    assert_eq!(aliased.minimum_action, "review");
}

#[cfg(unix)]
fn devin(payload: Value, home: &std::path::Path) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_source(
        "devin",
        "PreToolUse",
        &payload,
        None,
        None,
        home.to_str(),
        home.to_str(),
    )
}

/// A real temporary "home" so `~` expansion and canonicalization resolve
/// against fixture files the same way they resolve against the verified
/// envelope roots at runtime.
#[cfg(unix)]
fn devin_home() -> std::path::PathBuf {
    // Keep the fixture root outside $TMPDIR: on macOS it canonicalizes
    // under /private/var, which the sensitive-root check must reject.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-devin")
        .join(format!("home-{}", std::process::id()));
    for file in [
        "project/state/current_run.json",
        "project/pyproject.toml",
        "project/scripts/notes.txt",
        "project/credentials.txt",
        "project/.env",
        ".ssh/id_rsa",
        ".hol-support/SAFETY.md",
    ] {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "fixture").unwrap();
    }
    std::fs::create_dir_all(root.join("project/sub")).unwrap();
    // Canonicalize once so callers never spell the root with `..` segments,
    // which the traversal guard rejects.
    std::fs::canonicalize(&root).unwrap()
}

#[cfg(unix)]
#[test]
fn devin_exec_uses_the_command_model() {
    let home = devin_home();
    let pwd = devin(
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "exec",
            "tool_input": {"command": "pwd"}
        }),
        &home,
    );
    assert_eq!(pwd.action.action_type, PreToolActionTypeV1::Command);
    assert_eq!(pwd.minimum_action, "allow");

    let destructive = devin(
        json!({
            "tool_name": "exec",
            "tool_input": {"command": "rm -rf /"}
        }),
        &home,
    );
    assert_eq!(destructive.minimum_action, "block");

    let compound = devin(
        json!({
            "tool_name": "exec",
            "tool_input": {"command": "pwd; rm -rf ~"}
        }),
        &home,
    );
    assert_ne!(compound.minimum_action, "allow");
}

#[cfg(unix)]
#[test]
fn devin_reads_allow_only_bounded_existing_files() {
    let home = devin_home();
    let home_str = home.to_string_lossy().into_owned();

    let home_relative = devin(
        json!({
            "tool_name": "read",
            "tool_input": {"file_path": "~/project/state/current_run.json"}
        }),
        &home,
    );
    assert_eq!(
        home_relative.action.action_type,
        PreToolActionTypeV1::FileRead
    );
    assert_eq!(home_relative.minimum_action, "allow");

    let absolute = devin(
        json!({
            "tool_name": "read",
            "tool_input": {"file_path": format!("{home_str}/project/pyproject.toml")}
        }),
        &home,
    );
    assert_eq!(absolute.minimum_action, "allow");

    // The harness safety guide has an explicit dot-directory exception.
    let safety = devin(
        json!({
            "tool_name": "read",
            "tool_input": {"file_path": "~/.hol-support/SAFETY.md"}
        }),
        &home,
    );
    assert_eq!(safety.minimum_action, "allow");

    // A grep whose path is a real file is a bounded read.
    let grep_file = devin(
        json!({
            "tool_name": "grep",
            "tool_input": {"pattern": "fixture", "path": "~/project/scripts/notes.txt"}
        }),
        &home,
    );
    assert_eq!(grep_file.minimum_action, "allow");

    // Directory scopes cannot prove which descendant files a recursive
    // search will touch, so they remain under review.
    let grep_dir = devin(
        json!({
            "tool_name": "grep",
            "tool_input": {"pattern": "fixture", "path": "~/project/scripts"}
        }),
        &home,
    );
    assert_eq!(grep_dir.action.action_type, PreToolActionTypeV1::FileRead);
    assert_ne!(grep_dir.minimum_action, "allow");

    let glob_dir = devin(
        json!({
            "tool_name": "glob",
            "tool_input": {"pattern": "*.json", "path": "~/project"}
        }),
        &home,
    );
    assert_ne!(glob_dir.minimum_action, "allow");

    // A symlink under the home root that escapes it must not auto-allow.
    #[cfg(unix)]
    {
        let escaped = home.join("project/etc-passwd-link");
        std::os::unix::fs::symlink("/etc/passwd", &escaped).unwrap();
        let via_symlink = devin(
            json!({
                "tool_name": "read",
                "tool_input": {"file_path": "~/project/etc-passwd-link"}
            }),
            &home,
        );
        assert_ne!(via_symlink.minimum_action, "allow");
    }

    for sensitive in [
        "~/project/.env",
        "~/project/credentials.txt",
        "~/.ssh/id_rsa",
        "~/project/state/missing.json",
        "~/project",
        "/etc/passwd",
        "/var/root/.ssh/id_rsa",
        "~root/project/file.json",
        "/opt/outside/file.txt",
        "/Users/other/notes.txt",
    ] {
        let result = devin(
            json!({
                "tool_name": "read",
                "tool_input": {"file_path": sensitive}
            }),
            &home,
        );
        assert_eq!(result.action.action_type, PreToolActionTypeV1::FileRead);
        assert_ne!(
            result.minimum_action, "allow",
            "{sensitive} must not auto-allow"
        );
    }

    // Without a verified home directory, `~/` targets cannot be proven
    // bounded and must stay under review.
    let no_home = evaluate_pre_tool_envelope(
        "devin",
        "PreToolUse",
        &json!({"tool_name": "read", "tool_input": {"file_path": "~/project/file.json"}}),
    );
    assert_ne!(no_home.minimum_action, "allow");

    // A workspace root also proves an absolute read bounded even when the
    // target is outside the home directory.
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-devin")
        .join(format!("workspace-{}", std::process::id()));
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("lib.py"), "fixture").unwrap();
    let workspace = std::fs::canonicalize(&workspace).unwrap();
    let workspace_only = evaluate_pre_tool_envelope_with_source(
        "devin",
        "PreToolUse",
        &json!({"tool_name": "read", "tool_input": {"file_path": workspace.join("lib.py").to_string_lossy()}}),
        None,
        None,
        Some("/nonexistent-home"),
        workspace.to_str(),
    );
    assert_eq!(workspace_only.minimum_action, "allow");

    let write = devin(
        json!({
            "tool_name": "write",
            "tool_input": {"file_path": "~/project/state/out.json", "content": "{}"}
        }),
        &home,
    );
    assert_eq!(write.action.action_type, PreToolActionTypeV1::FileWrite);
    assert_eq!(write.minimum_action, "review");

    let mcp = devin(
        json!({
            "tool_name": "mcp__composio__COMPOSIO_MANAGE_CONNECTIONS",
            "tool_input": {"toolkits": []}
        }),
        &home,
    );
    assert_eq!(mcp.action.action_type, PreToolActionTypeV1::McpTool);
    assert_eq!(mcp.minimum_action, "review");
}

#[test]
fn bounds_reject_oversized_payload() {
    let oversized = generic(json!({"prompt": "x".repeat(MAX_COMMAND_BYTES + 1)}));
    assert_eq!(oversized.minimum_action, "block");
    assert_eq!(oversized.reason_code, "native_pre_tool_bounds_exceeded");
}
