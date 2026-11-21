//! Editor tasks that run on folder open and dev containers that run a command
//! on the host.
use super::*;

fn ids(config: EditorConfig, text: &str) -> Vec<&'static str> {
    detect_editor_task_risk(config, text)
        .rules
        .into_iter()
        .map(|rule| rule.id)
        .collect()
}

const FOLDER_OPEN: &str = r#"{
  // Starts as soon as the folder opens.
  "version": "2.0.0",
  "tasks": [
    {
      "label": "setup",
      "type": "shell",
      "command": "node .vscode/setup.js",
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}"#;

#[test]
fn a_task_that_runs_on_folder_open_is_reported_through_comments_and_trailing_commas() {
    let check = detect_editor_task_risk(EditorConfig::Tasks, FOLDER_OPEN);
    assert_eq!(check.rules, vec![FOLDER_OPEN_TASK]);
    assert!(check.parsed);
}

#[test]
fn folder_open_is_found_in_any_case_platform_override_or_workspace_file() {
    for text in [
        r#"{"tasks": [{"runOptions": {"runOn": "FolderOpen"}}]}"#,
        r#"{"tasks": [{"label": "a", "osx": {"runOptions": {"runOn": "folderOpen"}}}]}"#,
        r#"{"folders": [{"path": "."}], "tasks": {"version": "2.0.0", "tasks": [{"runOptions": {"runOn": "folderOpen"}}]}}"#,
        r#"{"tasks": [{"runOptions": {"runOn": "folderOpen"}}]}"#,
    ] {
        assert_eq!(
            ids(EditorConfig::Tasks, text),
            vec![FOLDER_OPEN_TASK.id],
            "{text}"
        );
    }
}

#[test]
fn ordinary_tasks_and_commented_out_folder_open_are_quiet() {
    for text in [
        r#"{"version": "2.0.0", "tasks": [{"label": "build", "command": "npm run build", "group": "build"}]}"#,
        r#"{"tasks": [{"label": "watch", "runOptions": {"runOn": "default"}}]}"#,
        "{\"tasks\": [{\"label\": \"watch\"\n// \"runOptions\": {\"runOn\": \"folderOpen\"}\n}]}",
        r#"{"tasks": [{"label": "a", /* "runOptions": {"runOn": "folderOpen"} */ "command": "make"}]}"#,
        r#"{"tasks": [{"label": "a", "command": "echo \"runOn\": \"folderOpen\""}]}"#,
        r#"{"tasks": [{"label": "a", "detail": "set runOn to folderOpen to start on open"}]}"#,
    ] {
        let check = detect_editor_task_risk(EditorConfig::Tasks, text);
        assert!(check.rules.is_empty(), "{text}");
        assert!(check.parsed, "{text}");
    }
}

#[test]
fn a_string_holding_comment_markers_is_not_cut_short() {
    let text = r#"{"tasks": [{"command": "curl https://example.test/x", "runOptions": {"runOn": "folderOpen"}}]}"#;
    assert_eq!(ids(EditorConfig::Tasks, text), vec![FOLDER_OPEN_TASK.id]);
}

#[test]
fn an_unparsed_file_is_matched_by_text_and_reported_unparsed() {
    let text = r#"{"tasks": [{"runOptions": {"runOn": "folderOpen"}} "#;
    let check = detect_editor_task_risk(EditorConfig::Tasks, text);
    assert_eq!(check.rules, vec![FOLDER_OPEN_TASK]);
    assert!(!check.parsed);
    let quiet = detect_editor_task_risk(EditorConfig::Tasks, "{\"tasks\": [");
    assert!(quiet.rules.is_empty());
    assert!(!quiet.parsed);
}

#[test]
fn a_dev_container_initialize_command_in_any_form_is_reported() {
    for text in [
        r#"{"name": "app", "initializeCommand": "bash .devcontainer/init.sh"}"#,
        r#"{"initializeCommand": ["bash", "init.sh"]}"#,
        r#"{"initializeCommand": {"setup": "bash init.sh"},}"#,
        "{\n  // host setup\n  \"initializeCommand\": \"./init.sh\",\n}",
    ] {
        assert_eq!(
            ids(EditorConfig::DevContainer, text),
            vec![DEVCONTAINER_INITIALIZE.id],
            "{text}"
        );
    }
}

#[test]
fn container_side_commands_and_empty_initialize_commands_are_quiet() {
    for text in [
        r#"{"image": "mcr.microsoft.com/devcontainers/base", "postCreateCommand": "npm ci"}"#,
        r#"{"onCreateCommand": "make", "postStartCommand": ["npm", "start"]}"#,
        r#"{"initializeCommand": ""}"#,
        r#"{"initializeCommand": "   "}"#,
        r#"{"initializeCommand": []}"#,
        r#"{"initializeCommand": {}}"#,
        r#"{"initializeCommand": null}"#,
        r#"{"customizations": {"initializeCommand": "x"}}"#,
        "{\n// \"initializeCommand\": \"./init.sh\"\n\"image\": \"x\"}",
    ] {
        assert!(ids(EditorConfig::DevContainer, text).is_empty(), "{text}");
    }
}

#[test]
fn an_unparsed_dev_container_is_matched_by_text() {
    let check = detect_editor_task_risk(
        EditorConfig::DevContainer,
        r#"{"initializeCommand": "./init.sh" "image": "x"}"#,
    );
    assert_eq!(check.rules, vec![DEVCONTAINER_INITIALIZE]);
    assert!(!check.parsed);
    for empty in [
        r#"{"initializeCommand": "" "image": "x"}"#,
        r#"{"initializeCommand": "   " "image": "x"}"#,
    ] {
        let check = detect_editor_task_risk(EditorConfig::DevContainer, empty);
        assert!(check.rules.is_empty(), "{empty}");
        assert!(!check.parsed);
    }
}

#[test]
fn a_file_saved_with_a_byte_order_mark_parses() {
    let tasks = format!("\u{feff}{FOLDER_OPEN}");
    let check = detect_editor_task_risk(EditorConfig::Tasks, &tasks);
    assert_eq!(check.rules, vec![FOLDER_OPEN_TASK]);
    assert!(check.parsed);
    let quiet = detect_editor_task_risk(EditorConfig::DevContainer, "\u{feff}{\"image\": \"x\"}");
    assert!(quiet.rules.is_empty());
    assert!(quiet.parsed);
}

#[test]
fn each_rule_reports_fixed_wording() {
    for rule in [FOLDER_OPEN_TASK, DEVCONTAINER_INITIALIZE] {
        assert!(!rule.title.is_empty() && rule.title.len() <= 120);
        assert!(!rule.reason.is_empty() && rule.reason.len() <= 1024);
        assert!(rule
            .false_positive_hint
            .is_some_and(|hint| hint.len() <= 1024));
    }
}
