#![cfg(windows)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_runtime_windows_process::is_single_link_file;
use serde_json::json;
use std::path::Path;

#[path = "support/git_helper_fixture.rs"]
pub mod fixture;

#[test]
fn windows_home_writes_verify_real_file_link_counts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/windows-home-writes")
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
    let other = home.join("other-project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let ordinary = other.join("ordinary.txt");
    let linked = other.join("linked.txt");
    std::fs::write(&ordinary, "ordinary fixture").unwrap();
    std::fs::write(&linked, "hard-link fixture").unwrap();
    std::fs::hard_link(&linked, other.join("linked-alias.txt")).unwrap();
    let symlink = other.join("symbolic-link.txt");
    std::os::windows::fs::symlink_file(&ordinary, &symlink)
        .expect("Windows regression runner must support file symlinks");
    assert!(is_single_link_file(&symlink).is_err());
    assert!(is_single_link_file(&ordinary).unwrap());
    assert!(!is_single_link_file(&linked).unwrap());
    assert!(is_single_link_file(&other).is_err());
    assert!(is_single_link_file(&other.join("missing.txt")).is_err());
    for (path, allowed) in [
        (ordinary, true),
        (other.join("new.txt"), true),
        (linked, false),
        (symlink, false),
        (other.join("linked-alias.txt"), false),
        (other.join(".env"), false),
        (home.join("AppData/Roaming/Editor/settings.json"), false),
        (root.join("foreign-home/new.txt"), false),
    ] {
        let result = evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name":"write","tool_input":{"path":path,"content":"fixture"}}),
            None,
            None,
            home.to_str(),
            workspace.to_str(),
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{}: {}",
            path.display(),
            result.reason_code
        );
    }
}
