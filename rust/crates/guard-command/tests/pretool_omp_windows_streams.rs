#![cfg(windows)]
use serde_json::json;
use std::path::Path;

use crate::git_helper_fixture as fixture;

#[test]
fn ntfs_stream_spellings_are_judged_as_the_omp_selectors_they_spell() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/omp-windows-streams")
        .join(format!(
            "{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let _cleanup = fixture::FixtureCleanup(root.clone());
    std::fs::create_dir_all(&root).unwrap();
    let canonical_root = std::fs::canonicalize(&root).unwrap();
    let spelling = canonical_root.to_str().unwrap();
    let root = std::path::PathBuf::from(spelling.strip_prefix(r"\\?\").unwrap_or(spelling));
    let home = root.join("home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("calc.py"), "print(1)\n").unwrap();
    // A stat of these spellings fails with an invalid-name error, not
    // NotFound. Each one is read the way Unix reads it: one line window plus
    // `raw` reads lines of `calc.py`, and any other compound is reviewed.
    for (path, allowed) in [
        ("calc.py:1-5:raw", true),
        ("calc.py:raw:1-5", true),
        ("calc.py:raw:raw", false),
        ("calc.py:1-5:raw:raw", false),
    ] {
        let result = fixture::evaluate_pre_tool_envelope_with_context(
            "omp",
            "PreToolUse",
            &json!({"tool_name": "read", "tool_input": {"path": path}}),
            None,
            None,
            Some(home.to_str().unwrap()),
            workspace.to_str(),
        );
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{path}: {}",
            result.reason_code
        );
    }
}
