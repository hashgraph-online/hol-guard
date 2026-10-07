use serde_json::json;

#[path = "support/git_helper_fixture.rs"]
pub mod fixture;

#[test]
fn forged_worktree_metadata_cannot_hide_external_execution_configuration() {
    let root = std::env::temp_dir().join(format!(
        "guard-forged-worktree-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _cleanup = fixture::FixtureCleanup(root.clone());
    let home = root.join("home");
    let workspace = home.join("workspace");
    let common = root.join("external-common");
    let admin = common.join("worktrees/workspace");
    for path in [
        &workspace,
        &admin,
        &common.join("objects"),
        &common.join("refs"),
    ] {
        std::fs::create_dir_all(path).unwrap();
    }
    std::fs::write(common.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        common.join("config"),
        "[core]\nrepositoryformatversion = 0\nfsmonitor = ./synthetic-never-execute\n",
    )
    .unwrap();
    std::fs::write(admin.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", workspace.join(".git").display()),
    )
    .unwrap();
    std::fs::write(
        workspace.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    let result = fixture::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":"git -C . status --short"}}),
        Some(&fixture::github_controls("enabled")),
        None,
        home.to_str(),
        workspace.to_str(),
    );
    assert_eq!(result.minimum_action, "require-reapproval");
    assert_eq!(result.reason_code, "native_git_execution_context_review");
    assert!(!result.explicitly_benign);
    let write = guard_command::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"write","tool_input":{"path":workspace.join(".git"),"content":"synthetic"}}),
        None,
        None,
        home.to_str(),
        workspace.to_str(),
    );
    assert_ne!(write.minimum_action, "allow");
}
