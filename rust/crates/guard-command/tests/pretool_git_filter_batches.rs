#[path = "support/git_helper_fixture.rs"]
mod fixture;
use fixture::*;
use serde_json::json;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn large_attribute_inventory_is_checked_without_executing_filters() {
    let root = std::env::temp_dir().join(format!("guard-filter-batches-{}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    let marker = root.join("filter-executed");
    let marker_command = format!(
        "touch '{}'",
        marker
            .to_string_lossy()
            .replace('\\', "/")
            .replace('\'', "'\\''")
    );
    let quoted = serde_json::to_string(&marker_command).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!("[filter \"synthetic\"]\nclean = {quoted}\nsmudge = {quoted}\n"),
    )
    .unwrap();
    assert!(Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    let mut hash = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash.stdin
        .take()
        .unwrap()
        .write_all(b"ordinary fixture\n")
        .unwrap();
    let output = hash.wait_with_output().unwrap();
    assert!(output.status.success());
    let oid = String::from_utf8(output.stdout).unwrap();
    let mut entries = String::new();
    let mut input_bytes = 0;
    let mut output_bytes = 0;
    let mut last = String::new();
    for index in 0..12000 {
        let path = format!("src/{}/{index:05}.txt", "ordinary".repeat(8));
        input_bytes += path.len() + 1;
        output_bytes += path.len() + 20;
        entries.push_str(&format!("100644 {}\t{path}\n", oid.trim()));
        last = path;
    }
    assert!(input_bytes < 1024 * 1024);
    assert!(output_bytes > 1024 * 1024);
    let mut index = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["update-index", "--index-info"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    index
        .stdin
        .take()
        .unwrap()
        .write_all(entries.as_bytes())
        .unwrap();
    assert!(index.wait().unwrap().success());
    let controls = github_controls("enabled");
    let inspect = || {
        evaluate_pre_tool_envelope_with_context(
            "generic",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":"git status --short"}}),
            Some(&controls),
            None,
            home.to_str(),
            repository.to_str(),
        )
    };
    let result = inspect();
    assert_eq!(result.decision, "allow", "{}", result.reason_code);
    std::fs::write(
        repository.join(".gitattributes"),
        format!("{last} filter=synthetic\n"),
    )
    .unwrap();
    let result = inspect();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.reason_code, "native_git_execution_context_review");
    assert!(
        !marker.exists(),
        "inspection must not execute configured filters"
    );
}
