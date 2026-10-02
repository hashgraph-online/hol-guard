use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn routine_workspace_writes_keep_sensitive_and_destructive_boundaries() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/workspace-write-fixtures")
        .join(format!("run-{}", std::process::id()));
    let workspace = root.join("project");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::create_dir_all(workspace.join(".ssh")).unwrap();
    std::fs::create_dir_all(workspace.join("Library/LaunchAgents")).unwrap();
    std::fs::write(workspace.join("src/example.py"), "fixture").unwrap();
    std::fs::write(root.join("outside.py"), "fixture").unwrap();
    let workspace = std::fs::canonicalize(workspace).unwrap();
    for (tool, path, allowed) in [
        ("edit", "src/example.py".to_owned(), true),
        ("write", "src/new.py".to_owned(), true),
        ("write", ".env".to_owned(), false),
        ("write", ".ssh/id_rsa".to_owned(), false),
        ("write", ".git/config".to_owned(), false),
        (
            "write",
            "Library/LaunchAgents/background.plist".to_owned(),
            false,
        ),
        ("write", "src/server.key".to_owned(), false),
        ("write", "src/krb5cc_1000".to_owned(), false),
        ("write", "../outside.py".to_owned(), false),
        (
            "write",
            root.join("outside.py").to_string_lossy().into_owned(),
            false,
        ),
        ("delete", "src/example.py".to_owned(), false),
        ("edit", "src".to_owned(), false),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": tool, "tool_input": {"path": path, "content": "print(1 + 1)"}}),
            None,
            None,
            workspace.to_str(),
            workspace.to_str(),
        );
        assert_eq!(result.minimum_action == "allow", allowed, "{tool}: {path}");
    }
    #[cfg(unix)]
    {
        let link = workspace.join("src/escape.py");
        if link.symlink_metadata().is_err() {
            std::os::unix::fs::symlink(root.join("outside.py"), &link).unwrap();
        }
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "write", "tool_input": {"path": link, "content": "fixture"}}),
            None,
            None,
            workspace.to_str(),
            workspace.to_str(),
        );
        assert_ne!(result.minimum_action, "allow");
    }
}
