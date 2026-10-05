#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::Path;
use std::process::Command;

fn permitted(command: &str, home: &Path, workspace: &Path) -> bool {
    let evaluate = |harness| {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"toolName": "Bash", "toolInput": {"command": command}}),
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        )
        .minimum_action
    };
    let zcode = evaluate("zcode");
    assert_eq!(zcode, evaluate("omp"), "host policy drift: {command}");
    zcode == "allow"
}

#[test]
fn ordinary_copies_keep_source_and_destination_risk_boundaries() {
    // Avoid macOS's protected /private/var temporary root.
    let home = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-copies")
        .join(format!("home-{}", std::process::id()));
    let project = home.join("project");
    let linked = home.join("linked");
    let outside = home.join("outside");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec![
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "fixture",
        ],
    ] {
        assert!(Command::new("git")
            .args(args)
            .current_dir(&project)
            .status()
            .unwrap()
            .success());
    }
    assert!(Command::new("git")
        .args(["worktree", "add", "--quiet", "--detach"])
        .arg(&linked)
        .current_dir(&project)
        .status()
        .unwrap()
        .success());
    for path in [
        project.join("source.ts"),
        project.join("auth.ts"),
        project.join(".env"),
        outside.join("source.ts"),
    ] {
        std::fs::write(path, "synthetic fixture").unwrap();
    }
    std::os::unix::fs::symlink(project.join(".env"), project.join("alias.ts")).unwrap();
    std::os::unix::fs::symlink(&outside, project.join("escaped")).unwrap();
    std::fs::hard_link(outside.join("source.ts"), outside.join("hardlink.ts")).unwrap();
    for directory in [outside.join("bin"), outside.join("Library/LaunchAgents")] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = std::fs::canonicalize(&home).unwrap();
    let project = std::fs::canonicalize(&project).unwrap();
    let linked = std::fs::canonicalize(&linked).unwrap();
    let outside = std::fs::canonicalize(&outside).unwrap();
    let temporary = Path::new("/tmp").join(format!("guard-copy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temporary);
    std::fs::create_dir(&temporary).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(temporary.join("existing.ts"), "synthetic previous copy").unwrap();
    std::fs::write(temporary.join("origin.ts"), "synthetic").unwrap();
    std::os::unix::fs::symlink(project.join("source.ts"), temporary.join("link.ts")).unwrap();
    std::fs::hard_link(temporary.join("origin.ts"), temporary.join("hardlink.ts")).unwrap();
    for command in [
        "cp source.ts copied.ts".to_owned(),
        "cp -- auth.ts copied.ts".to_owned(),
        "cp ~/outside/source.ts ~/project/copied.ts".to_owned(),
        "cp source.ts ~/outside/copied.ts".to_owned(),
        format!("cp source.ts {}/copied.ts", outside.display()),
        format!(
            "cp {}/source.ts {}/copied.ts",
            project.display(),
            linked.display()
        ),
        format!("cp source.ts {}/new.ts", temporary.display()),
        format!("cp source.ts {}/existing.ts", temporary.display()),
    ] {
        assert!(permitted(&command, &home, &project), "{command}");
    }
    for command in [
        "cp .env copied.ts",
        "cp alias.ts copied.ts",
        "cp source.ts .env",
        "cp source.ts alias.ts",
        "cp source.ts escaped/copied.ts",
        "cp source.ts ~/outside/hardlink.ts",
        "cp source.ts ~/outside/.env",
        "cp source.ts ~/outside/credentials.txt",
        "cp source.ts ~/outside/bin/tool",
        "cp source.ts ~/outside/Library/LaunchAgents/tool.plist",
        "cp source.ts .git/config",
        "cp -r source.ts copied.ts",
        "cp -f source.ts copied.ts",
        "cp . copied.ts",
        "cp source.ts one.ts two.ts",
        "cp source.ts copied.ts > output.txt",
        "cp source.ts copied.ts && echo done",
        "cp source.ts copied.ts | cat",
    ] {
        assert!(!permitted(command, &home, &project), "{command}");
    }
    for name in [
        ".env",
        "link.ts",
        "hardlink.ts",
        ".git/config",
        "credentials.txt",
    ] {
        let command = format!("cp source.ts {}/{name}", temporary.display());
        assert!(!permitted(&command, &home, &project), "{command}");
    }
    std::fs::remove_dir_all(temporary).unwrap();
}
