#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn word_counts_do_not_gain_secret_or_file_list_access() {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/word-count-fixtures");
    std::fs::create_dir_all(&fixtures).unwrap();
    let mut attempt = 0;
    let root = loop {
        let candidate = fixtures.join(format!("fixture-{}-{attempt}", std::process::id()));
        match std::fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
            Err(error) => panic!("failed to create fixture directory: {error}"),
        }
    };
    let _fixture = FixtureDirectory(root.clone());
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::write(root.join("one.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(root.join("two.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(root.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    // A killed prior run can leave fixture-{pid} and its -l symlink behind;
    // create_dir_all tolerates the dir but symlink() does not. Drop a stale
    // link first so PID reuse across container restarts is not flaky.
    let link = root.join("-l");
    if link.symlink_metadata().is_ok() {
        std::fs::remove_file(&link).unwrap();
    }
    std::os::unix::fs::symlink(root.join(".env"), &link).unwrap();
    for harness in ["omp", "zcode"] {
        for (command, allowed) in [
            ("wc -l one.txt", true),
            ("wc -lwmc one.txt two.txt", true),
            ("wc --lines one.txt", true),
            ("wc -- one.txt", true),
            ("cat one.txt | wc -l", true),
            ("cat one.txt | wc -- -", true),
            ("cat one.txt | wc", true),
            ("wc -l .env", false),
            ("cat .env | wc -l", false),
            ("wc one.txt -l", false),
            ("wc -- -l", false),
            ("wc --files0-from=one.txt", false),
            ("wc --files0-from .env", false),
            ("wc one.txt --files0-from=.env", false),
            ("cat one.txt | wc --files0-from=.env", false),
            ("wc -l", false),
            ("wc -l one.txt; rm -rf project", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"bash", "tool_input":{"command":command}}),
                None,
                None,
                root.to_str(),
                root.to_str(),
            );
            assert_eq!(
                result.minimum_action == "allow",
                allowed,
                "{harness}: {command}"
            );
        }
    }
}
