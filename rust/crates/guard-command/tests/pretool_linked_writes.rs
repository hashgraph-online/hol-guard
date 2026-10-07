#![cfg(any(unix, windows))]

use serde_json::json;

#[path = "support/git_helper_fixture.rs"]
pub mod fixture;
use fixture::evaluate_pre_tool_envelope_with_context;

#[test]
fn workspace_writes_do_not_follow_hard_links_to_protected_files() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/linked-write-fixtures")
        .join(format!(
            "case-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = fixture::FixtureCleanup(root.clone());
    let canonical_home = std::fs::canonicalize(&root).unwrap();
    // Model the caller's drive or UNC path, not canonicalize's device prefix.
    let spelling = canonical_home.to_str().unwrap();
    let home = if let Some(unc) = spelling.strip_prefix(r"\\?\UNC\") {
        std::path::PathBuf::from(format!(r"\\{unc}"))
    } else {
        std::path::PathBuf::from(spelling.strip_prefix(r"\\?\").unwrap_or(spelling))
    };
    let workspace = home.join("project");
    std::fs::create_dir(&workspace).unwrap();
    let protected = home.join(".env");
    std::fs::write(&protected, "SYNTHETIC_ONLY=unchanged\n").unwrap();
    std::fs::hard_link(&protected, workspace.join("alias.txt")).unwrap();
    std::fs::write(workspace.join("source.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(workspace.join("existing.txt"), "ordinary fixture\n").unwrap();
    std::fs::create_dir(workspace.join("existing-directory")).unwrap();

    for harness in ["omp", "claude-code"] {
        for command in ["mkdir -p existing-directory", "mkdir new-directory"] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
                None,
                None,
                home.to_str(),
                workspace.to_str(),
            );
            assert_eq!(
                result.minimum_action, "allow",
                "{harness}: {command}: {result:?}"
            );
        }
        for (destination, allowed) in [
            ("alias.txt", false),
            ("existing.txt", true),
            ("new.txt", true),
        ] {
            for (input, input_allowed) in [
                (
                    json!({"tool_name":"write", "tool_input":{"path": destination, "content":"replacement\n"}}),
                    allowed,
                ),
                (
                    json!({"tool_name":"edit", "tool_input":{"path": destination, "oldText":"ordinary", "newText":"replacement"}}),
                    allowed,
                ),
                (
                    json!({"tool_name":"Bash", "tool_input":{"command":format!("cp source.txt {destination}")}}),
                    allowed,
                ),
                (
                    json!({"tool_name":"Bash", "tool_input":{"command":format!("touch {destination}")}}),
                    allowed,
                ),
            ] {
                let result = evaluate_pre_tool_envelope_with_context(
                    harness,
                    "PreToolUse",
                    &input,
                    None,
                    None,
                    home.to_str(),
                    workspace.to_str(),
                );
                assert_eq!(
                    result.minimum_action == "allow",
                    input_allowed,
                    "{harness}: {input}: {result:?}"
                );
            }
        }
    }
    assert_eq!(
        std::fs::read_to_string(protected).unwrap(),
        "SYNTHETIC_ONLY=unchanged\n"
    );
}
