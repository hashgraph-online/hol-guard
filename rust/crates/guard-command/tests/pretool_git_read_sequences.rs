#[path = "support/git_helper_fixture.rs"]
pub mod fixture;
use fixture::*;
use serde_json::json;

const FLOOR: &str = "native_git_execution_context_review";

fn git(repository: &std::path::Path, home: &std::path::Path, arguments: &[&str]) {
    let mut command = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(name);
    }
    let status = command
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn reason(home: &std::path::Path, cwd: &std::path::Path, command: &str) -> String {
    let controls = github_controls("enabled");
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .reason_code
}

// Agents look around before they read history. A read-only listing writes no
// configuration, so it cannot change what the later Git read runs.
#[test]
fn read_only_segments_before_a_git_read_keep_its_proof() {
    let root = std::env::temp_dir().join(format!("guard read sequence {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    let outside = root.join("outside");
    for directory in [&home, &repository, &outside] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = home.canonicalize().unwrap();
    let repository = repository.canonicalize().unwrap();
    let outside = outside.canonicalize().unwrap();
    git(&repository, &home, &["init", "--quiet"]);
    git(
        &repository,
        &home,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &home, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join("package.json"), "{}\n").unwrap();
    git(&repository, &home, &["add", "-A"]);
    git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);

    for command in [
        "ls && cat package.json 2>/dev/null; git log --oneline -5",
        "ls -la && git status --short",
        "pwd && git diff --stat",
    ] {
        assert_ne!(reason(&home, &repository, command), FLOOR, "{command}");
    }
    // No repository: Git stops during setup and runs nothing.
    for command in ["git status", "git status 2>&1; ls -a"] {
        assert_ne!(reason(&home, &outside, command), FLOOR, "{command}");
    }

    // The configuration probe still sees a pager the read would launch.
    let marker = root.join("pager-ran").to_string_lossy().replace('\\', "/");
    git(
        &repository,
        &home,
        &["config", "core.pager", &format!("touch '{marker}'")],
    );
    // Either Git context check may stop it first; both keep the review.
    for command in ["git log --oneline -5", "ls && git log --oneline -5"] {
        let code = reason(&home, &repository, command);
        assert!(
            [FLOOR, "native_git_helper_context_review"].contains(&code.as_str()),
            "{command}: {code}"
        );
    }
}
