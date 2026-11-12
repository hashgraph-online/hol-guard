use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::*;

const PIN: &str = "11bd71901bbe5b1630ceea73d27597364c9af683";
const PWN_REQUEST: &str = "on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
";

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
        workflows: true,
        editor_tasks: false,
        instructions: false,
    }
}

fn scan(root: &Path) -> Value {
    snapshot(&request(root)).unwrap()["workflows"].clone()
}

fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn found(workflows: &Value) -> Vec<(String, String)> {
    workflows["findings"]
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
fn a_privileged_workflow_that_runs_pull_request_code_is_reported_without_its_text() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".github/workflows/ci.yml", PWN_REQUEST);

    let workflows = scan(root.path());

    assert_eq!(workflows["schema"], "guard.workspace-workflows.v1");
    assert_eq!(workflows["detector_version"], "ci-workflow-v1");
    assert_eq!(workflows["status"], "complete");
    assert_eq!(workflows["files_scanned"], 1);
    let path = ".github/workflows/ci.yml".to_owned();
    assert_eq!(
        found(&workflows),
        [
            (path.clone(), "ci.workflow.unpinned-action".to_owned()),
            (path.clone(), "ci.workflow.untrusted-checkout".to_owned()),
            (path, "ci.workflow.write-all-permissions".to_owned()),
        ]
    );
    let text = workflows.to_string();
    for quoted in ["actions/checkout", "head.sha", "npm ci", "@v4"] {
        assert!(!text.contains(quoted), "{quoted}");
    }
    let finding = &workflows["findings"][1];
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["category"], "execution");
    assert_eq!(finding["finding_id"].as_str().unwrap().len(), 32);
    assert!(finding.get("event").is_none());
}

#[test]
fn only_yaml_files_directly_in_the_root_workflow_directory_are_read() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".github/workflows/release.yaml", PWN_REQUEST);
    for ignored in [
        ".github/workflows/nested/ci.yml",
        ".github/workflows/README.md",
        ".github/actions/setup/action.yml",
        "packages/app/.github/workflows/ci.yml",
        "ci.yml",
    ] {
        write(root.path(), ignored, PWN_REQUEST);
    }

    let workflows = scan(root.path());

    assert_eq!(workflows["files_scanned"], 1);
    assert!(found(&workflows)
        .iter()
        .all(|(path, _)| path == ".github/workflows/release.yaml"));
}

#[test]
fn pinned_narrow_workflows_and_a_project_without_workflows_are_quiet_and_complete() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        ".github/workflows/ci.yml",
        &format!(
            "on: [push, pull_request]\npermissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@{PIN} # v4\n      - uses: ./.github/actions/setup\n      - run: cargo test\n"
        ),
    );
    write(root.path(), ".github/dependabot.yml", "version: 2\n");

    let workflows = scan(root.path());
    assert_eq!(workflows["status"], "complete");
    assert_eq!(workflows["files_scanned"], 1);
    assert!(found(&workflows).is_empty());

    let empty = tempfile::tempdir().unwrap();
    write(empty.path(), "README.md", "hello");
    let workflows = scan(empty.path());
    assert_eq!(workflows["status"], "complete");
    assert_eq!(workflows["files_scanned"], 0);
}

#[test]
fn a_workflow_that_is_not_text_leaves_the_scan_incomplete() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".github/workflows/ci.yml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, [0xff, 0xfe, b'o', b'n']).unwrap();

    let workflows = scan(root.path());

    assert_eq!(workflows["status"], "incomplete");
    assert_eq!(
        workflows["truncation_reasons"],
        json!(["workflow_not_text"])
    );
}

#[test]
fn a_workflow_the_snapshot_left_out_leaves_the_scan_incomplete() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".github/workflows/ci.yml", PWN_REQUEST);
    let mut request = request(root.path());
    request.max_file_bytes = 16;

    let workflows = snapshot(&request).unwrap()["workflows"].clone();

    assert_eq!(workflows["status"], "incomplete");
    assert_eq!(workflows["skipped"]["unread"], 1);
    assert!(workflows["truncation_reasons"]
        .as_array()
        .unwrap()
        .contains(&json!("workflow_unread")));
    assert!(found(&workflows).is_empty());
}

#[cfg(unix)]
#[test]
fn a_linked_workflow_leaves_the_scan_incomplete() {
    for (link, target) in [
        (".github/workflows/ci.yml", "shared/workflows/ci.yml"),
        (".github/workflows", "shared/workflows"),
        (".github", "shared"),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "shared/workflows/ci.yml", PWN_REQUEST);
        let path = root.path().join(link);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(root.path().join(target), &path).unwrap();

        let workflows = scan(root.path());

        assert_eq!(workflows["status"], "incomplete", "{link}");
        assert_eq!(workflows["truncation_reasons"], json!(["workflow_linked"]));
    }

    let root = tempfile::tempdir().unwrap();
    write(root.path(), "shared/notes.md", "notes");
    std::os::unix::fs::symlink(root.path().join("shared"), root.path().join("docs")).unwrap();
    assert_eq!(scan(root.path())["status"], "complete");
}

#[test]
fn findings_are_stable_and_one_per_rule_and_workflow() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".github/workflows/a.yml", PWN_REQUEST);
    write(root.path(), ".github/workflows/b.yml", PWN_REQUEST);

    let first = scan(root.path());
    let second = scan(root.path());

    assert_eq!(first["findings"], second["findings"]);
    let ids: std::collections::BTreeSet<&str> = first["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["finding_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 6);
}

#[test]
fn the_workflow_scan_runs_only_when_asked_and_needs_content_mode() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), ".github/workflows/ci.yml", PWN_REQUEST);
    let mut request = request(root.path());
    let with_workflows = snapshot(&request).unwrap();
    request.workflows = false;
    let without = snapshot(&request).unwrap();

    assert!(without.get("workflows").is_none());
    assert_eq!(
        with_workflows["snapshot_digest"],
        without["snapshot_digest"]
    );

    request.workflows = true;
    request.mode = SnapshotMode::Stat;
    assert_eq!(
        snapshot(&request).unwrap_err(),
        "workspace_snapshot_workflows_need_content"
    );
}
