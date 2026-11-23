use super::wrapper_plan;
use crate::pretool::workspace_contained_tests::workspace;

const HOME: &str = "home";

#[cfg(unix)]
fn sibling_root(name: &str) -> std::path::PathBuf {
    let root =
        std::path::Path::new("/tmp").join(format!("guard-plan-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".git")).expect("sibling .git");
    std::fs::write(root.join(".git/config"), "[core]\n\tbare = false\n").expect("config");
    std::fs::write(root.join("package.json"), "{}").expect("manifest");
    root.canonicalize().expect("sibling root")
}

/// A list in a sibling root keeps each run's own filter stage, as issued.
///
/// An agent steps into a checkout beside the session, checks its state, then
/// runs its tests and reads the summary line out of the output. The rejoin
/// used to write back only a `head` or `tail` bound for a list, so the whole
/// command lost its containment and was judged from the session workspace
/// instead, where every step after the `cd` is outside the sandbox.
#[cfg(unix)]
#[test]
fn a_list_in_a_sibling_root_keeps_the_filter_stage_each_run_was_issued_with() {
    let root = sibling_root("list-filter");
    let session = workspace("plan-list-filter", true);
    let workspace_path = session.to_str().expect("workspace path");
    for (command, core) in [
        (
            format!(
                "cd {} && git status --short && pytest -q 2>&1 | grep -E \"passed\"",
                root.display()
            ),
            "git status --short && pytest -q 2>&1 | grep -E passed",
        ),
        (
            format!(
                "cd {} && pytest -q 2>&1 | cut -c1-120 && ruff check .",
                root.display()
            ),
            "pytest -q 2>&1 | cut -c1-120 && ruff check .",
        ),
    ] {
        let plan = wrapper_plan(
            &command,
            workspace_path,
            Some(workspace_path),
            Some(HOME),
            false,
        )
        .plan
        .unwrap_or_else(|| panic!("rejoined in the sibling root: {command}"));
        assert_eq!(plan.core, core, "{command}");
        assert_eq!(
            std::fs::canonicalize(&plan.directory).expect("directory"),
            root,
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
