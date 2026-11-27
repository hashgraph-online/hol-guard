#![cfg(unix)]
//! Agents clear a scratch file before they look at history:
//! `rm -f /tmp/notes.txt; git log --oneline -1`. A removal of the user's own
//! temporary file that holds no configuration section leaves what Git reads
//! as it was, so the Git read keeps its configuration proof.
use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, github_controls, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const FLOOR: &str = "native_git_execution_context_review";

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn evaluate(home: &Path, cwd: &Path, command: &str) -> (String, String) {
    let controls = github_controls("enabled");
    let decision = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    );
    (decision.minimum_action, decision.reason_code)
}

#[test]
fn a_temporary_file_removal_before_a_git_read_keeps_its_proof() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-read-after-temporary-removal")
        .join(std::process::id().to_string());
    let _ = std::fs::remove_dir_all(&root);
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    for directory in [&home, &repository] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = home.canonicalize().unwrap();
    let repository = repository.canonicalize().unwrap();
    fixture::git(&home, &repository, &["init", "--quiet"]);
    fixture::git(
        &home,
        &repository,
        &["config", "user.email", "fixture@example.test"],
    );
    fixture::git(&home, &repository, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join("package.json"), "{}\n").unwrap();
    fixture::git(&home, &repository, &["add", "-A"]);
    fixture::git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);

    let scratch = PathBuf::from(format!("/tmp/hg-git-read-removal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _scratch = Scratch(scratch.clone());
    std::fs::write(scratch.join("notes.txt"), "draft commit message\n").unwrap();
    std::fs::write(scratch.join("out.patch"), "--- a/x\n+++ b/x\n").unwrap();
    // A file a configuration could include: removing it drops its settings.
    std::fs::write(scratch.join("extra.conf"), "[pager]\n\tlog = false\n").unwrap();
    std::fs::write(scratch.join(".mailmap"), "Fixture <fixture@example.test>\n").unwrap();
    let scratch = scratch.display();
    let absent = format!("/tmp/hg-git-read-removal-absent-{}.txt", std::process::id());

    for command in [
        format!("rm -f {scratch}/notes.txt; git log --oneline -1"),
        format!("rm -f {scratch}/out.patch {absent} 2>/dev/null; git status --short"),
        format!("rm -f {absent} && git diff --stat"),
    ] {
        let (action, reason) = evaluate(&home, &repository, &command);
        assert_ne!(reason, FLOOR, "{command}");
        assert_eq!(action, "allow", "{command}: {reason}");
    }

    for command in [
        // A file with a configuration section may be included by one.
        format!("rm -f {scratch}/extra.conf; git log --oneline -1"),
        // A dotfile can be an attributes, ignore or mailmap file.
        format!("rm -f {scratch}/.mailmap; git log --oneline -1"),
        // Only Git commands that never write the work tree join the chain.
        format!("rm -f {scratch}/notes.txt; git checkout -- package.json"),
        format!("rm -f {scratch}/notes.txt; git stash"),
        // A copy keeps the chain to its plain peers.
        format!("rm -f {absent}; cp package.json {scratch}/copy.json; git log --oneline -1"),
        // One unproven operand keeps the whole step unproven.
        format!("rm -f {scratch}/notes.txt {scratch}/extra.conf; git log --oneline -1"),
    ] {
        let (action, reason) = evaluate(&home, &repository, &command);
        assert_ne!(action, "allow", "{command}: {reason}");
    }
}
