use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new(name: &str) -> Self {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(name);
        std::fs::create_dir_all(&base).unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut attempt = 0;
        loop {
            let root = base.join(format!("run-{}-{nonce}-{attempt}", std::process::id()));
            match std::fs::create_dir(&root) {
                Ok(()) => return Self(root.canonicalize().unwrap()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
                Err(error) => panic!("failed to create test root: {error}"),
            }
        }
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn shell_read_commands_share_the_structured_file_risk_boundary() {
    let fixture = TestRoot::new("shell-read-fixtures");
    let home = &fixture.0;
    let workspace = home.join("project");
    let outside = home.join("other");
    for directory in [&workspace, &outside] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("auth_example.ts"),
            "protection-graph/ fixture",
        )
        .unwrap();
        std::fs::write(directory.join(".env"), "SYNTHETIC=fixture").unwrap();
    }
    let commands = [
        "grep -n 'protection-graph/'",
        "grep -nE 'password|api_key|token'",
        "rg -n 'protection-graph/'",
        "cat",
        "head -n 10",
        "tail -n 10",
        "sed -n '1,10p'",
    ];
    for prefix in commands {
        for target in [
            workspace.join("auth_example.ts").display().to_string(),
            outside.join("auth_example.ts").display().to_string(),
            "~/other/auth_example.ts".to_owned(),
            "auth_example.ts".to_owned(),
        ] {
            let command = format!("{prefix} '{target}'");
            let result = evaluate_pre_tool_envelope_with_context(
                "zcode",
                "PreToolUse",
                &json!({"toolName":"Bash", "toolInput":{"command":command}}),
                None,
                None,
                home.to_str(),
                workspace.to_str(),
            );
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        let command = format!("{prefix} '{}'", outside.join(".env").display());
        let result = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName":"Bash", "toolInput":{"command":command}}),
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        );
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.join(".env"), workspace.join("source-link.ts")).unwrap();
        let command = format!(
            "grep -n fixture '{}'",
            workspace.join("source-link.ts").display()
        );
        let result = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName":"Bash", "toolInput":{"command":command}}),
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        );
        assert_ne!(
            result.minimum_action, "allow",
            "secret symlink must remain guarded"
        );
    }
}

#[test]
fn zcode_home_relative_edits_accept_verified_home_and_preserve_sensitive_boundaries() {
    let fixture = TestRoot::new("worktree-write-fixtures");
    let home = &fixture.0;
    let workspace = home.join("project");
    let linked = home.join("linked");
    let linked_path = linked.to_str().unwrap();
    let linked_path = linked_path.strip_prefix(r"\\?\").unwrap_or(linked_path);
    let hooks = home.join("empty-fixture-hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    let git = |arguments: &[&str]| {
        let output = std::process::Command::new("git")
            .current_dir(&workspace)
            .arg("-c")
            .arg(format!("core.hooksPath={}", hooks.display()))
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "--quiet"]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "fixture",
    ]);
    git(&["worktree", "add", "--quiet", "--detach", linked_path]);
    for directory in [&workspace, &linked, &home.join("unrelated")] {
        std::fs::create_dir_all(directory.join("src")).unwrap();
        std::fs::write(directory.join("src/example.ts"), "fixture").unwrap();
    }
    let marker = std::fs::read_to_string(linked.join(".git")).unwrap();
    let admin = std::path::Path::new(marker.trim().strip_prefix("gitdir: ").unwrap());
    std::fs::write(admin.join("gitdir"), "../../../../linked/.git\n").unwrap();
    let relative = evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({"toolName":"Write", "toolInput":{"file_path":"~/linked/app/api/relative/route.ts", "content":"fixture"}}),
        None,
        None,
        home.to_str(),
        Some("~/project"),
    );
    assert_eq!(relative.minimum_action, "allow", "{}", relative.reason_code);
    for (path, allowed) in [
        ("~/project/src/example.ts", true),
        ("~/linked/src/example.ts", true),
        ("~/linked/src/new.ts", true),
        ("~/linked/app/api/backfill/route.ts", true),
        ("~/linked/app/api/backfill/.env", false),
        ("~/linked/.ssh/new/id_rsa", false),
        ("~/linked/.env", false),
        ("~/linked/.git", false),
        ("~/unrelated/src/example.ts", true),
        ("~other/project/src/example.ts", false),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName": "Edit", "toolInput": {"file_path": path, "old_string": "fixture", "new_string": "updated"}}),
            None,
            None,
            home.to_str(),
            Some("~/project"),
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{path}: {}",
            result.reason_code
        );
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            home.join("unrelated/src/example.ts"),
            linked.join("src/escape.ts"),
        )
        .unwrap();
        let result = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName": "Edit", "toolInput": {"file_path": "~/linked/src/escape.ts", "new_string": "updated"}}),
            None,
            None,
            home.to_str(),
            Some("~/project"),
        );
        assert_ne!(result.minimum_action, "allow");
    }
}

#[test]
fn routine_workspace_writes_keep_sensitive_and_destructive_boundaries() {
    let fixture = TestRoot::new("workspace-write-fixtures");
    let root = &fixture.0;
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
        ("write", "app/api/backfill/route.ts".to_owned(), true),
        ("write", "src/example.py/nested/new.py".to_owned(), false),
        ("write", "app/api/backfill/.env".to_owned(), false),
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
        std::os::unix::fs::symlink(
            root.join("missing-directory"),
            workspace.join("dangling-parent"),
        )
        .unwrap();
        let dangling = evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName":"Write", "toolInput":{"file_path":"dangling-parent/nested/new.py", "content":"fixture"}}),
            None,
            None,
            workspace.to_str(),
            workspace.to_str(),
        );
        assert_ne!(dangling.minimum_action, "allow");
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
