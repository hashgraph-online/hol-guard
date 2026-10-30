//! The root a workspace sandbox runs from when the call's absolute script
//! lies in a sibling repository.

use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// A private home holding the session's repository, a sibling one with a
/// script, and a plain directory with one. `/tmp`, not `$TMPDIR`: macOS puts
/// the latter below `/private/var`, which the path proofs judge as its own
/// location rather than a home. The returned handle removes the fixture.
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new()
        .prefix("guard-sink-sibling-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = directory.path().to_path_buf();
    let projects = root.join("home/projects");
    for directory in ["app/.git", "report/.git", "report/scripts", "plain"] {
        fs::create_dir_all(projects.join(directory)).unwrap();
    }
    for repository in ["app", "report"] {
        let config = projects.join(repository).join(".git/config");
        fs::write(config, "[core]\n\tbare = false\n").unwrap();
    }
    for project in ["app", "report", "plain"] {
        fs::write(projects.join(project).join("package.json"), "{}").unwrap();
    }
    fs::write(projects.join("report/scripts/report.py"), "").unwrap();
    fs::write(projects.join("plain/probe.py"), "").unwrap();
    let root = root.canonicalize().unwrap();
    (directory, root)
}

fn sibling_root(command: &str, workspace: &str, home: &Path) -> Option<PathBuf> {
    let payload: Map<String, Value> =
        serde_json::from_value(json!({ "tool_input": { "command": command } })).unwrap();
    super::sibling_root(&payload, workspace, home)
}

#[test]
fn a_script_in_a_sibling_repository_runs_from_its_root() {
    let (_fixture, root) = fixture();
    let (home, projects) = (root.join("home"), root.join("home/projects"));
    let workspace = projects.join("app");
    let workspace = workspace.to_str().unwrap();
    let report = projects.join("report");
    let sibling = format!("python3 {}/scripts/report.py --top 40", report.display());
    assert_eq!(sibling_root(&sibling, workspace, &home), Some(report));
    for command in [
        // The workspace's own script runs from the workspace.
        "python3 scripts/report.py".to_owned(),
        // A script outside any repository roots nothing.
        format!("python3 {}/plain/probe.py", projects.display()),
        // A list is not one command; its `cd` form is planned on its own.
        format!(
            "python3 {}/scripts/report.py && ls",
            projects.join("report").display()
        ),
    ] {
        assert_eq!(sibling_root(&command, workspace, &home), None, "{command}");
    }
}
