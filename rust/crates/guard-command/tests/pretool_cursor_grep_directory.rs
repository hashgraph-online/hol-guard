//! Cursor's `Grep` tool searches a folder the way Claude Code's does, but its
//! hook names the folder `file_path`. No folder search of Cursor's had a
//! proof, so every one was held for review, even a search of the project's
//! own source. A folder that holds a file named for a secret, a search that
//! leaves the work tree, and an input Guard does not model keep the review.

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::layout;
use serde_json::{json, Value};
use std::path::Path;

fn cursor_grep(cwd: &Path, home: &Path, tool_input: Value) -> String {
    let result = fixture::evaluate_pre_tool_envelope_with_context(
        "cursor",
        "PreToolUse",
        &json!({
            "hook_event_name": "PreToolUse",
            "conversation_id": "fixture-conversation",
            "cursor_version": "2026.11.17",
            "tool_name": "Grep",
            "tool_use_id": "fixture-tool-use",
            "workspace_roots": [cwd.to_str().unwrap()],
            "tool_input": tool_input,
        }),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    );
    format!("{} {}", result.decision, result.reason_code)
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn cursor_grep_of_a_project_folder_is_allowed() {
    let layout = layout("cursor-grep-folder");
    let cwd = layout.org.join("app-portal");
    write(&cwd.join("src/routes.ts"), "export const routes = [];\n");
    write(
        &cwd.join("src/mcp_setup.ts"),
        "export const inert = true;\n",
    );
    write(&cwd.join("docs/notes.md"), "# Notes\n");
    let src = cwd.join("src");
    let sibling = layout.org.join("service-api").join("src");
    for input in [
        json!({"file_path": src, "pattern": "export", "output_mode": "content"}),
        json!({"file_path": src, "glob": "*mcp*", "output_mode": "content", "pattern": "inert|enable"}),
        json!({"file_path": src, "glob": "*.ts", "output_mode": "files_with_matches", "pattern": "routes"}),
        json!({"file_path": cwd.join("docs"), "pattern": "Notes", "-i": true, "head_limit": 20}),
        json!({"file_path": "src", "pattern": "export"}),
        json!({"file_path": sibling, "pattern": "fixture"}),
    ] {
        let outcome = cursor_grep(&cwd, &layout.home, input.clone());
        assert!(outcome.starts_with("allow "), "{input}: {outcome}");
    }
}

#[test]
fn cursor_grep_that_could_reach_a_secret_keeps_its_review() {
    let layout = layout("cursor-grep-folder-negative");
    let cwd = layout.org.join("app-portal");
    write(&cwd.join("config/settings.ts"), "export const port = 1;\n");
    write(&cwd.join("config/.env"), "PORT=1\n");
    write(&cwd.join("keys/notes.md"), "# Keys\n");
    write(&cwd.join("keys/credentials.json"), "{}\n");
    // Ignored by Git, but a search that does not honor the ignore file still
    // opens it.
    write(&cwd.join("build/.gitignore"), "*\n");
    write(&cwd.join("build/.env.production"), "STAGE=fixture\n");
    write(&layout.home.join(".ssh/config"), "Host fixture\n");
    let config = cwd.join("config");
    for input in [
        json!({"file_path": config, "pattern": "PORT|port"}),
        json!({"file_path": cwd.join("keys"), "glob": "*.json", "pattern": "a|b"}),
        json!({"file_path": cwd.join("build"), "pattern": "fix.*"}),
        json!({"file_path": layout.home.join(".ssh"), "pattern": "Host"}),
        json!({"file_path": "/etc", "pattern": "root"}),
        json!({"file_path": cwd.join("../.."), "pattern": "export"}),
        // An empty pattern lists every file the search reaches.
        json!({"file_path": cwd.join("src"), "pattern": ""}),
        // A key Guard does not model could widen the search.
        json!({"file_path": cwd.join("src"), "pattern": "fixture", "follow": true}),
        // Two different folders in one request.
        json!({"file_path": cwd.join("src"), "path": config, "pattern": "export"}),
    ] {
        let outcome = cursor_grep(&cwd, &layout.home, input.clone());
        assert!(!outcome.starts_with("allow "), "{input}: {outcome}");
    }
}
