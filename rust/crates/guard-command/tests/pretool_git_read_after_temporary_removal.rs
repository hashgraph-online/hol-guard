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
    // The repository's `info/attributes` is this file, and a macro defined
    // elsewhere can make `quiet` unset a filter.
    std::fs::write(scratch.join("quiet.txt"), "*.txt quiet\n").unwrap();
    std::fs::create_dir_all(repository.join(".git/info")).unwrap();
    std::os::unix::fs::symlink(
        scratch.join("quiet.txt"),
        repository.join(".git/info/attributes"),
    )
    .unwrap();
    // A directory outside every checkout to run the routed steps from.
    let outside = scratch.join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    let scratch = scratch.display();
    let absent = format!("/tmp/hg-git-read-removal-absent-{}.txt", std::process::id());

    for command in [
        format!("rm -f {scratch}/notes.txt; git log --oneline -1"),
        format!("rm -f {scratch}/out.patch {absent} 2>/dev/null; git status --short"),
        format!("rm -f {absent} && git diff --stat"),
        format!("rm -f {absent}; git log --oneline -1"),
    ] {
        let (action, reason) = evaluate(&home, &repository, &command);
        assert_ne!(reason, FLOOR, "{command}");
        assert_eq!(action, "allow", "{command}: {reason}");
        // The command proof itself admits the chain, not the enabled Git
        // permission, so default permissions allow it too.
        assert_eq!(reason, "native_exact_safe_command", "{command}");
    }

    for command in [
        // A file with a configuration section may be included by one.
        format!("rm -f {scratch}/extra.conf; git log --oneline -1"),
        // An attributes file Git reads keeps the review whatever it holds.
        format!("rm -f {scratch}/quiet.txt; git log --oneline -1"),
        format!("rm -f {scratch}/quiet.txt 2>/dev/null && git status --short"),
        // A dotfile can be an attributes, ignore or mailmap file.
        format!("rm -f {scratch}/.mailmap; git log --oneline -1"),
        // Only Git commands that never write the work tree join the chain.
        format!("rm -f {scratch}/notes.txt; git checkout -- package.json"),
        format!("rm -f {scratch}/notes.txt; git stash"),
        // A copy keeps the chain to its plain peers.
        format!("rm -f {absent}; cp package.json {scratch}/copy.json; git log --oneline -1"),
        // One unproven operand keeps the whole step unproven.
        format!("rm -f {scratch}/notes.txt {scratch}/extra.conf; git log --oneline -1"),
        // A step that sets its own configuration may name the removed file.
        format!("rm -f {scratch}/notes.txt; git -c core.attributesFile={scratch}/notes.txt log --oneline -1"),
    ] {
        let (action, reason) = evaluate(&home, &repository, &command);
        assert_ne!(action, "allow", "{command}: {reason}");
    }

    // A Git step routed with `-C` reads that repository's attributes, so
    // the removal is checked against them from any working directory.
    let routed = repository.display();
    let command = format!("rm -f {scratch}/notes.txt; git -C {routed} log --oneline -1");
    assert_eq!(
        evaluate(&home, &outside, &command),
        ("allow".to_owned(), "native_exact_safe_command".to_owned()),
        "{command}"
    );
    for command in [
        format!("rm -f {scratch}/quiet.txt; git -C {routed} log --oneline -1"),
        format!("rm -f {scratch}/quiet.txt && git -C {routed} status --short"),
    ] {
        let (action, reason) = evaluate(&home, &outside, &command);
        assert_ne!(action, "allow", "{command}: {reason}");
    }
}

#[test]
fn a_removal_inside_the_git_directory_or_of_an_attributes_file_keeps_the_review() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-read-after-git-directory-removal")
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

    // The repository keeps its Git directory in the temporary folder.
    let scratch = PathBuf::from(format!("/tmp/hg-git-dir-removal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _scratch = Scratch(scratch.clone());
    let admin = scratch.join("admin");
    fixture::git(
        &home,
        &repository,
        &[
            "init",
            "--quiet",
            "--separate-git-dir",
            admin.to_str().unwrap(),
        ],
    );
    fixture::git(
        &home,
        &repository,
        &["config", "user.email", "fixture@example.test"],
    );
    fixture::git(&home, &repository, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join("package.json"), "{}\n").unwrap();
    fixture::git(&home, &repository, &["add", "-A"]);
    fixture::git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::create_dir_all(admin.join("info")).unwrap();
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(admin.join("info"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(admin.join("info").join("attributes"), "*.json text\n").unwrap();
    std::fs::write(scratch.join("notes.txt"), "draft commit message\n").unwrap();
    // A global attributes file can unset a filter the read relied on.
    std::fs::write(scratch.join("attributes.txt"), "* -filter\n").unwrap();
    std::fs::write(scratch.join("drivers.txt"), "*.json diff=json\n").unwrap();
    let scratch = scratch.display();
    let admin = admin.display();

    let command = format!("rm -f {scratch}/notes.txt; git log --oneline -1");
    let (action, reason) = evaluate(&home, &repository, &command);
    assert_eq!(
        (action.as_str(), reason.as_str()),
        ("allow", "native_exact_safe_command"),
        "{command}"
    );

    for command in [
        format!("rm -f {admin}/info/attributes; git status --short"),
        format!("rm -f {admin}/description; git log --oneline -1"),
        format!("rm -f {scratch}/attributes.txt; git status --short"),
        format!("rm -f {scratch}/drivers.txt; git diff --stat"),
    ] {
        let (action, reason) = evaluate(&home, &repository, &command);
        assert_ne!(action, "allow", "{command}: {reason}");
    }
}
