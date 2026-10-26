//! OMP reads of a sibling project spelled below macOS's `/tmp` alias, outside
//! both the home and the session directory.

use std::path::Path;

fn read(target: &str, home: &Path, cwd: &Path) -> guard_contracts::PreToolResultV1 {
    super::super::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "read",
            "tool_input": {"path": target},
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

#[test]
fn omp_selectors_map_tmp_alias_for_sibling_projects() {
    let tmp = Path::new("/tmp");
    if std::fs::canonicalize(tmp).ok().as_deref() != Some(Path::new("/private/tmp")) {
        return;
    }
    let root = tmp.join(format!("guard-sibling-tmp-alias-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    let sibling = root.join("sibling-project");
    let source = sibling.join("src").join("main.rs");
    let outside = root.join("outside.rs");
    let link = sibling.join("linked.rs");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, "fn main() {}\n").unwrap();
    std::fs::write(&outside, "outside\n").unwrap();
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    // Harnesses report the canonical session paths.
    let home = std::fs::canonicalize(&home).unwrap();
    let project = std::fs::canonicalize(&project).unwrap();

    for (target, reason_code) in [
        (
            format!("{}:1-5", source.display()),
            "native_exact_safe_file_read",
        ),
        (
            format!("{}:1-5", sibling.join("src").display()),
            "native_exact_safe_directory_read",
        ),
    ] {
        let decision = read(&target, &home, &project);
        assert_eq!(decision.minimum_action, "allow", "{target}");
        assert_eq!(decision.reason_code, reason_code, "{target}");
    }
    // Only the fixed alias is mapped: a link below it keeps its review.
    let linked = format!("{}:1-5", link.display());
    let decision = read(&linked, &home, &project);
    assert_ne!(decision.minimum_action, "allow", "{linked}");
    assert!(!decision.explicitly_benign, "{linked}");

    let _ = std::fs::remove_dir_all(root);
}
