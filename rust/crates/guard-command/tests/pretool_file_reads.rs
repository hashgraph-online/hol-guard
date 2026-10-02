use guard_command::pretool::evaluate_pre_tool_envelope;
#[cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
#[cfg(unix)]
use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
use serde_json::json;
#[cfg(unix)]
use serde_json::Value;

#[test]
fn zcode_identical_argument_aliases_preserve_single_file_read() {
    let result = evaluate_pre_tool_envelope(
        "zcode",
        "PreToolUse",
        &json!({
            "toolName": "Read", "tool_name": "Read",
            "toolInput": {"file_path": "src/example.rs"},
            "tool_input": {"file_path": "src/example.rs"}
        }),
    );
    assert_eq!(result.minimum_action, "allow");
    assert_eq!(result.reason_code, "native_exact_safe_file_read");
    for other in ["src/other.rs", ".env", ".ssh/id_rsa"] {
        let result = evaluate_pre_tool_envelope(
            "zcode",
            "PreToolUse",
            &json!({
                "toolName": "Read", "tool_name": "Read",
                "toolInput": {"file_path": "src/example.rs"},
                "tool_input": {"file_path": other}
            }),
        );
        assert_ne!(result.minimum_action, "allow", "{other}");
    }
}

#[cfg(unix)]
fn devin(payload: Value, home: &std::path::Path) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
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
        "project/tls/server.key",
        "project/krb5cc_1000",
        "project/.env",
        ".ssh/id_rsa",
        ".hol-support/SAFETY.md",
        ".agents/skills/example/SKILL.md",
        ".agents/skills/example/reference/operate.md",
        ".agents/skills/example/.hidden.md",
        ".agents/skills/example/credentials.md",
        ".agents/skills/example/run.py",
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
fn zcode_reads_skill_documents_but_not_hidden_or_sensitive_skill_files() {
    let home = devin_home();
    for (path, allowed) in [
        ("~/.agents/skills/example/SKILL.md", true),
        ("~/.agents/skills/example/reference/operate.md", true),
        ("~/.agents/skills/example/.hidden.md", false),
        ("~/.agents/skills/example/credentials.md", false),
        ("~/.agents/skills/example/run.py", false),
        ("~/.ssh/id_rsa", false),
        ("~/project/tls/server.key", false),
        ("~/project/krb5cc_1000", false),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName": "Read", "tool_name": "Read",
                "toolInput": {"file_path": path}, "tool_input": {"file_path": path}}),
            None,
            None,
            home.to_str(),
            home.to_str(),
        );
        assert_eq!(result.minimum_action == "allow", allowed, "{path}");
    }
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
    let outside_workspace = devin(
        json!({"tool_name": "Read", "tool_input": {
            "file_path": workspace.join("lib.py").to_string_lossy()
        }}),
        &home,
    );
    assert_eq!(outside_workspace.minimum_action, "allow");
    let workspace_only = evaluate_pre_tool_envelope_with_context(
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

#[cfg(unix)]
#[test]
fn skill_links_and_safety_guide_keep_their_verified_scope() {
    let root = devin_home().join("linked-scope");
    let home = root.join("home");
    let docs = root.join("docs");
    for file in [
        docs.join("example/SKILL.md"),
        root.join(".hol-support/SAFETY.md"),
        home.join(".hol-support/SAFETY.md"),
    ] {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "fixture").unwrap();
    }
    std::fs::create_dir_all(home.join(".agents")).unwrap();
    let link = home.join(".agents/skills");
    if !link.exists() {
        std::os::unix::fs::symlink(&docs, &link).unwrap();
    }
    let home = std::fs::canonicalize(home).unwrap();
    for (path, allowed) in [
        (link.join("example/SKILL.md"), true),
        (home.join(".hol-support/SAFETY.md"), true),
        (root.join(".hol-support/SAFETY.md"), false),
    ] {
        let result = devin(
            json!({"tool_name": "read", "tool_input": {"file_path": path}}),
            &home,
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{}",
            path.display()
        );
    }
}
