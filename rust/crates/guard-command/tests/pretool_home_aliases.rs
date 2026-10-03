#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::Path;

#[path = "support/git_helper_fixture.rs"]
pub mod fixture;

#[test]
fn aliased_home_root_allows_ordinary_files_but_not_redirected_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/home-aliases")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = fixture::FixtureCleanup(root.clone());
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("actual-home");
    let alias = root.join("home-alias");
    let workspace = home.join("project");
    let other = home.join("other-project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("existing.txt"), "ordinary fixture").unwrap();
    std::fs::write(other.join(".env"), "SYNTHETIC_ONLY=fixture").unwrap();
    std::os::unix::fs::symlink(&home, &alias).unwrap();
    std::os::unix::fs::symlink(other.join(".env"), other.join("redirected.txt")).unwrap();
    std::fs::hard_link(other.join("existing.txt"), other.join("hard-link.txt")).unwrap();
    std::fs::write(other.join("single.txt"), "ordinary fixture").unwrap();
    for (suffix, allowed) in [
        ("other-project/new.txt", true),
        ("other-project/./new.txt", true),
        ("other-project/single.txt", true),
        ("other-project/redirected.txt", false),
        ("other-project/hard-link.txt", false),
        ("other-project/.env", false),
        ("bin/tool", false),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"write","tool_input":{"path":alias.join(suffix),"content":"fixture"}}),
            None,
            None,
            alias.to_str(),
            workspace.to_str(),
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{suffix}: {}",
            result.reason_code
        );
    }
}
