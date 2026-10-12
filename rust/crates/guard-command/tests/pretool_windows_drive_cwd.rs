#![cfg(windows)]
use serde_json::json;
use std::path::Path;

#[path = "support/git_helper_fixture.rs"]
pub mod fixture;

#[test]
fn windows_drive_cwd_targets_bind_only_the_exact_workspace_spelling() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/windows-drive-cwd")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let _cleanup = fixture::FixtureCleanup(root.clone());
    std::fs::create_dir_all(&root).unwrap();
    let canonical_root = std::fs::canonicalize(&root).unwrap();
    let spelling = canonical_root.to_str().unwrap();
    let root = std::path::PathBuf::from(spelling.strip_prefix(r"\\?\").unwrap_or(spelling));
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::create_dir_all(workspace.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join("other")).unwrap();
    std::fs::write(workspace.join("src/one.ts"), "export const one = 1;\n").unwrap();
    std::os::windows::fs::symlink_dir(home.join("other"), workspace.join("alias"))
        .expect("Windows regression runner must support directory symlinks");
    std::os::windows::fs::symlink_dir(workspace.join("src"), workspace.join("linked")).unwrap();
    let init = std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&workspace)
        .status()
        .unwrap();
    assert!(init.success());
    let controls = fixture::github_controls("enabled");
    let cwd = workspace.to_str().unwrap();
    let forward = cwd.replace('\\', "/");
    let lowered = cwd.to_lowercase();
    for (command, allowed) in [
        (
            format!("cd '{cwd}' && mkdir -p output/generated/nested"),
            true,
        ),
        (format!("cd \"{cwd}\" && mkdir -p output"), true),
        (format!("cd {forward} && mkdir -p output"), true),
        (format!("cd '{cwd}' && cp src/one.ts src/copied.ts"), true),
        (format!("cd '{cwd}\\src' && cat one.ts"), true),
        (format!("cd '{lowered}' && mkdir -p output"), false),
        (format!("cd '{cwd}\\src\\..' && mkdir -p output"), false),
        (format!("cd '{cwd}\\..' && mkdir -p output"), false),
        (format!("cd '{cwd}\\alias' && mkdir -p output"), false),
        (format!("cd '{cwd}\\.ssh' && cat config"), false),
        (format!("cd '{cwd}\\linked' && cat one.ts"), false),
        // An unquoted backslash is removed by the shell, so it never proves a path.
        (format!("cd {cwd} && mkdir -p output"), false),
        (format!("cd \"{cwd}\\\\src\" && cat one.ts"), false),
        (format!("git --no-pager -C '{cwd}' status --short"), true),
        (format!("git --no-pager -C \"{cwd}\" status --short"), true),
        (format!("git --no-pager -C {cwd} status --short"), false),
        (
            format!("git --no-pager -C '{lowered}' status --short"),
            false,
        ),
        (
            format!("git --no-pager -C '{cwd}\\src\\..' status --short"),
            false,
        ),
        (
            format!("git --no-pager -C '{cwd}\\linked' status --short"),
            false,
        ),
        (
            format!("git --no-pager -C '{cwd}\\..' status --short"),
            false,
        ),
    ] {
        let result = fixture::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"bash","tool_input":{"command":command}}),
            Some(&controls),
            None,
            Some(home.to_str().unwrap()),
            Some(cwd),
        );
        assert_eq!(
            result.decision == "allow",
            allowed,
            "{command}: {}",
            result.reason_code
        );
    }
}
