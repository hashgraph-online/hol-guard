use super::*;
use std::fs;

fn target(raw_spec: &str, source_url: Option<&str>) -> Map<String, Value> {
    let mut target = json!({
        "ecosystem": "pypi",
        "raw_spec": raw_spec,
        "editable": false,
    })
    .as_object()
    .unwrap()
    .clone();
    if let Some(source_url) = source_url {
        target.insert("source_url".to_owned(), json!(source_url));
    }
    target
}

#[test]
fn an_archive_named_directory_is_still_inspected_as_a_local_project() {
    let workspace = tempfile::tempdir().expect("a workspace");
    let project = workspace.path().join("project-1.0.tar.gz");
    fs::create_dir(&project).expect("the project directory");
    fs::write(project.join("setup.py"), "from setuptools import setup\n").expect("a setup.py");

    // A local distribution file now carries its own path as its source. The
    // path still has to reach the on-disk inspection, because the name says
    // archive while the contents are a buildable project.
    assert_eq!(
        local_python_project_path(
            &target("./project-1.0.tar.gz", Some("./project-1.0.tar.gz")),
            workspace.path(),
        ),
        Some(project.clone()),
    );
    assert_eq!(
        local_python_project_path(&target("./project-1.0.tar.gz", None), workspace.path()),
        Some(project),
    );
}

#[test]
fn a_remote_source_still_names_no_local_project() {
    let workspace = tempfile::tempdir().expect("a workspace");
    for source_url in [
        "https://example.invalid/project-1.0.tar.gz",
        "git+https://example.invalid/project.git",
    ] {
        assert_eq!(
            local_python_project_path(&target("project", Some(source_url)), workspace.path()),
            None,
            "{source_url}",
        );
    }
}
